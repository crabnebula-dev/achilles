//! Capture source backed by the privileged helper daemon.
//!
//! The app connects to the root helper's Unix socket, sends the [`PidFilter`],
//! and receives [`CapturedEvent`]s the helper captures via `pktap` (real
//! per-app attribution, no sudo in the app). The helper is installed/launched
//! via `SMAppService` (see the app's helper-management code).

use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::source::{
    CaptureError, CaptureHandle, CaptureSource, CapturedEvent, PidFilter,
};
use crate::wire;

pub struct HelperSource;

#[async_trait::async_trait]
impl CaptureSource for HelperSource {
    fn backend_id(&self) -> &'static str {
        "macos-helper"
    }

    async fn start(
        &self,
        filter: PidFilter,
    ) -> Result<(mpsc::Receiver<CapturedEvent>, CaptureHandle), CaptureError> {
        let stream = UnixStream::connect(wire::HELPER_SOCKET_PATH)
            .await
            .map_err(|e| CaptureError::Unavailable(format!("privileged helper not reachable: {e}")))?;
        let (mut rd, mut wr) = stream.into_split();

        // Tell the helper which process to capture.
        wire::write_frame(&mut wr, &filter)
            .await
            .map_err(CaptureError::Io)?;

        let (tx, rx) = mpsc::channel(2048);
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel2.cancelled() => break,
                    frame = wire::read_frame::<_, CapturedEvent>(&mut rd) => {
                        match frame {
                            Ok(Some(ev)) => {
                                if tx.send(ev).await.is_err() {
                                    break;
                                }
                            }
                            _ => break, // EOF or error → helper stopped
                        }
                    }
                }
            }
            // Dropping the write half closes the connection, signalling the
            // helper to stop capturing for this session.
            drop(wr);
        });

        Ok((rx, CaptureHandle::new(cancel)))
    }
}
