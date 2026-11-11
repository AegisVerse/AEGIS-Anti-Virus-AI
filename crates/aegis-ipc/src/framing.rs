//! Async framing: 4-byte little-endian length prefix + UTF-8 payload.

use aegis_common::error::{AegisError, Result};
use aegis_common::protocol::{MAX_FRAME_BYTES, MAX_REQUEST_BYTES};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await.map_err(|e| AegisError::Io(e))?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len == 0 {
        return Err(AegisError::Parse("zero-length frame".into()));
    }
    if len > max_bytes || len > MAX_FRAME_BYTES {
        return Err(AegisError::Parse(format!("frame length {} exceeds maximum allowed {}", len, max_bytes)));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await.map_err(|e| AegisError::Io(e))?;
    Ok(buf)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME_BYTES {
        return Err(AegisError::Parse("outgoing frame exceeds maximum length".into()));
    }
    let len_bytes = (data.len() as u32).to_le_bytes();
    writer.write_all(&len_bytes).await.map_err(|e| AegisError::Io(e))?;
    writer.write_all(data).await.map_err(|e| AegisError::Io(e))?;
    writer.flush().await.map_err(|e| AegisError::Io(e))?;
    Ok(())
}

