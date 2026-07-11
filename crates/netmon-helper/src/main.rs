//! Achilles privileged capture helper.
//!
//! Runs as a root `LaunchDaemon` (installed/approved via `SMAppService` from the
//! main app). It listens on a local Unix socket; for each client it reads the
//! target [`PidFilter`], captures that process's traffic via `pktap`, and
//! streams [`CapturedEvent`]s back. Running as root is what makes `pktap`
//! per-app attribution work without the app itself being elevated.
//!
//! macOS-only in practice (pktap + Unix socket). On other platforms this is an
//! inert stub so the workspace still builds.

#[cfg(unix)]
#[tokio::main]
async fn main() {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    let path = netmon::wire::HELPER_SOCKET_PATH;
    let _ = std::fs::remove_file(path);
    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("achilles-netmon-helper: bind {path}: {e}");
            std::process::exit(1);
        }
    };
    // Reachable by the logged-in user. A hardening pass should restrict this to
    // the console user's uid via peer credentials (LOCAL_PEERCRED).
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
    eprintln!("achilles-netmon-helper: listening on {path}");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(serve(stream));
            }
            Err(e) => eprintln!("achilles-netmon-helper: accept: {e}"),
        }
    }
}

#[cfg(unix)]
async fn serve(stream: tokio::net::UnixStream) {
    use netmon::source::{CapturedEvent, PidFilter};
    use netmon::wire;
    use tokio::io::AsyncReadExt;

    let (mut rd, mut wr) = stream.into_split();

    // First frame is the target filter.
    let filter: PidFilter = match wire::read_frame(&mut rd).await {
        Ok(Some(f)) => f,
        _ => return,
    };

    #[cfg(target_os = "macos")]
    let source = netmon::direct_capture_source();
    #[cfg(not(target_os = "macos"))]
    let source: Box<dyn netmon::CaptureSource> = {
        let _ = &filter;
        let _ = wire::write_frame(
            &mut wr,
            &CapturedEvent::Warning("capture helper only implemented on macOS".into()),
        )
        .await;
        return;
    };

    #[cfg(target_os = "macos")]
    {
        let (mut rx, handle) = match source.start(filter).await {
            Ok(v) => v,
            Err(e) => {
                let _ = wire::write_frame(&mut wr, &CapturedEvent::Warning(e.to_string())).await;
                return;
            }
        };
        let mut probe = [0u8; 1];
        loop {
            tokio::select! {
                ev = rx.recv() => match ev {
                    Some(e) => {
                        if wire::write_frame(&mut wr, &e).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                // The app closing its write half (stop) surfaces as EOF here.
                r = rd.read(&mut probe) => {
                    if matches!(r, Ok(0) | Err(_)) {
                        break;
                    }
                }
            }
        }
        drop(handle); // stop capture
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("achilles-netmon-helper: unsupported platform");
}
