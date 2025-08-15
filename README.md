# Redis Entra Group Auth Proxy
There is currently a gap in the feature set of Azure Cache for Redis it doesn't allow Entra Group based authentication.
This proxy enables Redis clients to connect to Azure Cache for Redis using Azure AD (Entra ID) authentication. 
It authenticates users via JWT tokens and Entra Groups, uses Azure Managed Identity to securely connect to Redis.

## How It Works

1. The client connects to the proxy and sends an `AUTH` command with a JWT token.
2. The proxy validates the JWT token (signature, expiration, required groups).
3. The proxy obtains an access token for Redis using Azure Managed Identity.
4. The proxy connects to Redis, authenticates with the MI token, and forwards all subsequent commands.

## Running in Azure

When running in Azure, the proxy uses the Managed Identity service to obtain tokens automatically:

```bash
# Copy the example env file
cp .env.example .env

# Edit the .env file with your settings
vim .env

# Run the proxy
cargo run --release
```

## Running Outside Azure

You can run the proxy outside Azure using one of these methods:

### Method 1: Provide a Token Directly

Set the `LOCAL_REDIS_TOKEN` environment variable with a valid Azure AD token for Redis:

```bash
export LOCAL_REDIS_TOKEN="eyJ0eXAi..."
```

### Method 2: Use Azure CLI to Get a Token

Set the `LOCAL_REDIS_TOKEN_COMMAND` environment variable with a command that returns a token:

```bash
# Make sure you're logged in with az login first
export LOCAL_REDIS_TOKEN_COMMAND="az account get-access-token --resource https://redis.azure.com --query accessToken -o tsv"
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `LISTEN_ADDR` | Address and port to listen on (default: 0.0.0.0:6388) |
| `TENANT_ID` | Azure AD tenant ID |
| `EXPECTED_AUDIENCE` | Expected audience in JWT tokens |
| `REQUIRED_GROUP_IDS` | Comma-separated list of required Azure AD group object IDs |
| `REDIS_HOSTPORT` | Redis host:port (e.g., mycache.redis.cache.windows.net:6380) |
| `REDIS_HOSTNAME` | Redis hostname for TLS SNI (defaults to host part of REDIS_HOSTPORT) |
| `UAMI_CLIENT_ID` | User-assigned managed identity client ID (optional) |
| `REDIS_AAD_OBJECT_ID` | Object ID of the MI/SPN granted access to Redis |
| `LOCAL_REDIS_TOKEN` | For non-Azure: provide a Redis access token directly |
| `LOCAL_REDIS_TOKEN_COMMAND` | For non-Azure: command to execute to get a token |

## Client Configuration

Connect your Redis client to the proxy (default port 6388) and use your Azure AD JWT token for authentication:

```
redis-cli -h localhost -p 6388 -a "your.jwt.token"
```

## Building

```bash
cargo build --release
```

## Docker

```bash
docker build -t redis-entra-proxy .
docker run --env-file .env -p 6388:6388 redis-entra-proxy
```
