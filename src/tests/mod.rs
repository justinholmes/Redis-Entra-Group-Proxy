//! Tests module for the Redis Entra Proxy
//! 
//! Contains unit tests and integration tests for the application

use redis_entra_proxy::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use redis_protocol::resp2::decode::decode as resp2_decode;
use redis_protocol::resp2::types::OwnedFrame as Resp2Frame;
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::io::Cursor;
use std::collections::HashSet;
use anyhow::Result;

// Mock implementations for testing
mod mocks;

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
mod unit_tests;
