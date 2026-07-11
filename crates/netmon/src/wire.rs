//! Length-prefixed framing for the local socket between the app and the
//! privileged capture helper. The app sends a [`PidFilter`], the helper streams
//! [`CapturedEvent`]s back. Small, dependency-light JSON frames (the passive
//! handshake use case forwards few, small packets).

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Well-known socket the root helper listens on. In `/var/run` so it's created
/// by the (root) helper and reachable by the app.
pub const HELPER_SOCKET_PATH: &str = "/var/run/dev.crabnebula.achilles.netmon.sock";

/// Max frame size, guarding against a corrupt length prefix.
const MAX_FRAME: usize = 8 * 1024 * 1024;

pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(msg).map_err(invalid)?;
    w.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await
}

/// Read one frame, or `Ok(None)` on a clean EOF (peer closed).
pub async fn read_frame<R, T>(r: &mut R) -> std::io::Result<Option<T>>
where
    R: AsyncReadExt + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(invalid("frame too large"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(Some(serde_json::from_slice(&buf).map_err(invalid)?))
}

fn invalid<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}
