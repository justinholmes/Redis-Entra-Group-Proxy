//! Mocks for testing

use anyhow::Result;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// Mock TLS stream implementation
pub struct MockTlsStream<S> {
    pub inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for MockTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MockTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// Mock KeyStore for JWT validation
pub struct MockKeyStore;

pub enum MockJwksError {
    InvalidToken,
}

impl std::fmt::Debug for MockJwksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MockJwksError::InvalidToken => write!(f, "Invalid token"),
        }
    }
}

impl MockKeyStore {
    pub fn verify(&self, _jwt: &str) -> Result<String, MockJwksError> {
        // Always succeed in test
        Ok("verified".to_string())
    }
}
