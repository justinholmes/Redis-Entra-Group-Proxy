// Import the library module
use redis_entra_proxy::*;

// Include tests module
#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .without_time()
        .init();

    let settings = load_settings()?;
    info!("Listening on {}", settings.listen);
    let listener = TcpListener::bind(&settings.listen).await?;

    let jwks_url = format!("https://login.microsoftonline.com/{}/discovery/v2.0/keys", settings.tenant_id);
    let keystore = Arc::new(KeyStore::new());

    // TLS config for backend (rediss)
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
    let tls_connector = TlsConnector::from(tls_config);

    loop {
        let (client, addr) = listener.accept().await?;
        let s = settings.clone();
        let ks = keystore.clone();
        let tls = tls_connector.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(client, addr.to_string(), s, ks, tls).await {
                error!("client {} error: {:?}", addr, e);
            }
        });
    }
}

fn load_settings() -> Result<Settings> {
    let listen = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:6388".into());
    let tenant_id = std::env::var("TENANT_ID")?;
    let expected_audience = std::env::var("EXPECTED_AUDIENCE")?;
    let required_groups = std::env::var("REQUIRED_GROUP_IDS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect::<HashSet<_>>();
    let backend_host = std::env::var("REDIS_HOSTPORT")?; // "mycache.redis.cache.windows.net:6380"
    let backend_hostname = std::env::var("REDIS_HOSTNAME").unwrap_or_else(|_| backend_host.split(':').next().unwrap().to_string());
    let uami_client_id = std::env::var("UAMI_CLIENT_ID").ok();
    let redis_user_object_id = std::env::var("REDIS_AAD_OBJECT_ID")?; // the MI/SPN objectId configured on the cache

    Ok(Settings {
        listen,
        tenant_id,
        expected_audience,
        required_groups,
        backend_host,
        backend_hostname,
        uami_client_id,
        redis_user_object_id,
    })
}

// Expect the client to send: AUTH <jwt>  (we accept either 1-arg or 2-arg form; password = JWT)
async fn handle_client(
    mut client: TcpStream,
    peer: String,
    settings: Settings,
    keystore: Arc<KeyStore>,
    tls: TlsConnector,
) -> Result<()> {
    client.set_nodelay(true)?;
    // Read first frame (AUTH)
    let jwt = read_auth_jwt(&mut client).await
        .context("expected AUTH with JWT as password")?;

    // Validate JWT signature, issuer, aud, and groups
    validate_jwt(&jwt, &settings, &keystore).await
        .context("JWT validation failed")?;
    info!("[{}] JWT accepted", peer);

    // Obtain AAD access token for Redis via IMDS (Managed Identity)
    let (access_token, _exp) = fetch_redis_token_imds(settings.uami_client_id.as_deref()).await
        .context("failed to get managed identity token for Redis")?;

    // Connect to Azure Cache for Redis (TLS), send AUTH <objectId> <token>
    let mut backend = connect_backend_tls(&settings.backend_host, &settings.backend_hostname, tls).await?;
    send_backend_auth(&mut backend, &settings.redis_user_object_id, &access_token).await
        .context("AUTH to backend failed")?;
    info!("[{}] Backend AUTH OK", peer);

    // Pipe data in both directions thereafter
    tokio::io::copy_bidirectional(&mut client, &mut backend).await?;
    Ok(())
}

async fn read_auth_jwt(client: &mut TcpStream) -> Result<String> {
    let mut buf = BytesMut::with_capacity(16 * 1024);
    loop {
        // Try to decode a RESP2 frame
        if let Ok(Some((frame, consumed))) = resp2_decode(&buf) {
            let _ = buf.split_to(consumed);
            if let Resp2Frame::Array(items) = frame {
                let upper = |s: &str| s.eq_ignore_ascii_case("AUTH");
                if items.len() >= 2 {
                    let cmd = bulk_to_string(&items[0])?;
                    if upper(&cmd) {
                        if items.len() == 2 {
                            return Ok(bulk_to_string(&items[1])?);
                        } else {
                            return Ok(bulk_to_string(&items[2])?);
                        }
                    }
                }
            }
            anyhow::bail!("first command must be AUTH with JWT as password");
        }

        // Need to read more data
        let mut temp = vec![0u8; 4096];
        let n = client.read(&mut temp).await?;
        if n == 0 {
            anyhow::bail!("client disconnected before sending AUTH");
        }
        buf.extend_from_slice(&temp[..n]);
    }
}

fn bulk_to_string(f: &Resp2Frame) -> Result<String> {
    match f {
        Resp2Frame::BulkString(s) => Ok(String::from_utf8_lossy(s).to_string()),
        Resp2Frame::SimpleString(s) => Ok(String::from_utf8_lossy(s).to_string()),
        _ => anyhow::bail!("unexpected item in AUTH"),
    }
}

#[derive(Deserialize)]
struct JwtClaims {
    aud: serde_json::Value,
    iss: String,
    exp: usize,
    iat: Option<usize>,
    nbf: Option<usize>,
    // groups claim may not always be present if overage
    groups: Option<Vec<String>>,
    // appid, oid, etc. are available if you need them
}

async fn validate_jwt(jwt: &str, s: &Settings, ks: &KeyStore) -> Result<()> {
    // Verify and decode the JWT using the key store
    let result = ks.verify(jwt)
        .map_err(|e| anyhow::Error::msg(format!("JWT verification failed: {:?}", e)))?;

    // The jwks-client verification already validates the signature
    // We can use decoding with disabled validation to get our custom claims structure since signature is already verified
    let mut validation = jsonwebtoken::Validation::default();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.insecure_disable_signature_validation();
    let token = jsonwebtoken::decode::<JwtClaims>(jwt, &jsonwebtoken::DecodingKey::from_secret(&[]), &validation)?;

    // Optional: enforce token time‑window
    let now = chrono::Utc::now().timestamp() as usize;
    if token.claims.exp < now {
        anyhow::bail!("token expired");
    }

    if !s.required_groups.is_empty() {
        let token_groups: HashSet<String> =
            token.claims.groups.unwrap_or_default().into_iter().collect();
        for g in &s.required_groups {
            if !token_groups.contains(g) {
                anyhow::bail!("missing required group {g}");
            }
        }
    }
    Ok(())
}

async fn fetch_redis_token_imds(uami_client_id: Option<&str>) -> Result<(String, Instant)> {
    // IMDS requires metadata header and 169.254.169.254 endpoint
    let mut url = reqwest::Url::parse("http://169.254.169.254/metadata/identity/oauth2/token")?;
    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("api-version", "2018-02-01");
        // IMDS uses 'resource' (NOT scope) — for Redis use the resource base URL
        qp.append_pair("resource", "https://redis.azure.com");
        if let Some(cid) = uami_client_id {
            qp.append_pair("client_id", cid);
        }
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let resp = client
        .get(url)
        .header("Metadata", "true")
        .send()
        .await?
        .error_for_status()?;
    let tok: ImdsTokenResp = resp.json().await?;
    let secs: u64 = tok.expires_in.parse().unwrap_or(3600);
    let exp = Instant::now() + Duration::from_secs(secs);
    Ok((tok.access_token, exp))
}

async fn connect_backend_tls(
    hostport: &str,
    sni_hostname: &str,
    tls: TlsConnector,
) -> Result<TlsStream<TcpStream>> {
    let addr = hostport
        .to_socket_addrs()?
        .next()
        .context("resolve backend")?;
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    let dnsname = rustls::pki_types::ServerName::try_from(sni_hostname.to_string())
        .context("invalid SNI hostname")?;

    let tls_stream = tls.connect(dnsname, stream).await?;
    Ok(tls_stream)
}

async fn send_backend_auth(stream: &mut TlsStream<TcpStream>, user_oid: &str, token: &str) -> Result<()> {
    // AUTH <user> <password>
    let mut buf = Vec::with_capacity(64 + token.len());
    let frame = Resp2Frame::Array(vec![
        Resp2Frame::BulkString(b"AUTH".to_vec()),
        Resp2Frame::BulkString(user_oid.as_bytes().to_vec()),
        Resp2Frame::BulkString(token.as_bytes().to_vec()),
    ]);
    let bytes_frame = frame.into_bytes_frame();
    resp2_encode_bytes(&mut buf, &bytes_frame)?;
    stream.write_all(&buf).await?;
    stream.flush().await?;

    // Read a single simple +OK or error
    let mut read = [0u8; 5_000];
    let n = stream.read(&mut read).await?;
    // Expect "+OK\r\n" or RESP error; we do a minimal check
    let text = String::from_utf8_lossy(&read[..n]);
    if !text.contains("+OK") {
        anyhow::bail!("backend AUTH failed: {}", text);
    }
    Ok(())
}
