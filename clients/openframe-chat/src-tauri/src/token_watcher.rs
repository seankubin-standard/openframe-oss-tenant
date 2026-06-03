use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use crate::token_decryption_service::TokenDecryptionService;
use tauri::{AppHandle, Emitter};
use serde::Serialize;

#[derive(Clone, Serialize)]
struct TokenUpdateEvent {
    token: String,
}

/// Shared, cheaply-cloneable access to the decrypted auth token.
///
/// Two read paths:
///   - `read_fresh` decrypts the file on demand and updates the cache. Used on
///     the NATS reconnect path (`auth_url_callback`) and by `get_token` so a
///     (re)connect or a frontend refresh always sees the newest token the
///     daemon has written, with zero dependency on poll timing.
///   - `current` returns the last cached value without touching disk.
///
/// `TokenWatcher` shares the same cache and pushes `token-update` events to the
/// WebView when the file rotates.
#[derive(Clone)]
pub struct TokenSource {
    inner: Option<Arc<TokenSourceInner>>,
    cached: Arc<Mutex<Option<String>>>,
}

struct TokenSourceInner {
    path: PathBuf,
    decryptor: TokenDecryptionService,
}

impl TokenSource {
    pub fn new(path: String, decryptor: TokenDecryptionService) -> Self {
        Self {
            inner: Some(Arc::new(TokenSourceInner {
                path: PathBuf::from(path),
                decryptor,
            })),
            cached: Arc::new(Mutex::new(None)),
        }
    }

    /// A source with no token file (missing config). Always yields `None`.
    pub fn disabled() -> Self {
        Self {
            inner: None,
            cached: Arc::new(Mutex::new(None)),
        }
    }

    /// Reads + decrypts the token file now, refreshes the cache, returns it.
    pub fn read_fresh(&self) -> Option<String> {
        let Some(inner) = &self.inner else {
            return None;
        };
        let token = read_and_decrypt(&inner.path, &inner.decryptor);
        *self.cached.lock().unwrap() = token.clone();
        token
    }

    pub fn current(&self) -> Option<String> {
        self.cached.lock().unwrap().clone()
    }

    fn path(&self) -> Option<&Path> {
        self.inner.as_deref().map(|i| i.path.as_path())
    }
}

fn read_and_decrypt(path: &Path, decryptor: &TokenDecryptionService) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    match decryptor.decrypt(trimmed) {
        Ok(token) => Some(token),
        Err(e) => {
            log::error!("token watcher: failed to decrypt token: {}", e);
            None
        }
    }
}

/// Polls the token file for rotation and pushes `token-update` events to the
/// WebView. An mtime fast-path avoids re-decrypting an unchanged file.
pub struct TokenWatcher;

impl TokenWatcher {
    /// Spawns the watcher thread. No-op when the source is disabled.
    pub fn start(source: TokenSource, app_handle: AppHandle) {
        if source.path().is_none() {
            return;
        }

        std::thread::spawn(move || {
            let path = source.path().expect("enabled source has a path").to_path_buf();
            let mut last_mtime: Option<SystemTime> = None;

            loop {
                let mtime = fs::metadata(&path).and_then(|m| m.modified()).ok();
                // Re-decrypt only when the file mtime moved (or stat failed).
                if mtime.is_none() || mtime != last_mtime {
                    last_mtime = mtime;

                    let prev = source.current();
                    let new = source.read_fresh();
                    if prev != new {
                        if let Some(token) = &new {
                            match prev {
                                None => log::info!("token watcher: first token received"),
                                Some(_) => log::info!("token watcher: token refreshed"),
                            }
                            emit_token_to_frontend(&app_handle, token);
                        }
                    }
                }

                std::thread::sleep(Duration::from_secs(1));
            }
        });
    }
}

fn emit_token_to_frontend(app_handle: &AppHandle, token: &str) {
    let event = TokenUpdateEvent {
        token: token.to_string(),
    };
    match app_handle.emit("token-update", event) {
        Ok(_) => log::debug!("token watcher: token emitted to frontend"),
        Err(e) => log::error!("token watcher: failed to emit token-update event: {}", e),
    }
}
