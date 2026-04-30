use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use crate::token_decryption_service::TokenDecryptionService;
use tauri::{AppHandle, Emitter};
use serde::Serialize;
use tokio::sync::Notify;

#[derive(Clone, Serialize)]
struct TokenUpdateEvent {
    token: String,
}

/// Service that watches for token changes in the shared token enc file
pub struct TokenWatcher {
    token_file_path: PathBuf,
    current_token: Arc<Mutex<Option<String>>>,
    token_changed: Arc<Notify>,
    decryption_service: TokenDecryptionService,
    app_handle: AppHandle,
}

/// Tauri state to share the current token with commands.
///
/// `token_changed` is signalled (`notify_waiters`) every time the decrypted
/// token actually changes — the NATS bridge waits on it to coordinate
/// auth-fail reconnects with daemon-driven token rotation.
#[derive(Clone)]
pub struct TokenState {
    pub current_token: Arc<Mutex<Option<String>>>,
    pub token_changed: Arc<Notify>,
}

impl TokenWatcher {
    /// Creates a new TokenWatcher and starts watching for token changes in a background thread
    /// Returns TokenState that can be used in Tauri commands
    pub fn start(token_path: String, secret: String, app_handle: AppHandle) -> TokenState {
        let decryption_service = match TokenDecryptionService::new(secret) {
            Ok(service) => service,
            Err(e) => {
                log::error!("token watcher: failed to create decryption service: {}", e);
                // Return empty state on error
                return TokenState {
                    current_token: Arc::new(Mutex::new(None)),
                    token_changed: Arc::new(Notify::new()),
                };
            }
        };

        let current_token = Arc::new(Mutex::new(None));
        let token_changed = Arc::new(Notify::new());
        let token_state = TokenState {
            current_token: current_token.clone(),
            token_changed: token_changed.clone(),
        };

        let watcher = Self {
            token_file_path: PathBuf::from(token_path),
            current_token,
            token_changed,
            decryption_service,
            app_handle,
        };
        
        std::thread::spawn(move || {
            loop {
                watcher.check_and_update_token();
                std::thread::sleep(Duration::from_secs(5));
            }
        });
        
        token_state
    }

    /// Reads the encrypted token from file, decrypts it, and returns it
    fn read_and_decrypt_token(&self) -> Option<String> {
        match fs::read_to_string(&self.token_file_path) {
            Ok(encrypted_content) => {
                if encrypted_content.trim().is_empty() {
                    return None;
                }
                
                match self.decryption_service.decrypt(encrypted_content.trim()) {
                    Ok(decrypted) => Some(decrypted),
                    Err(e) => {
                        log::error!("token watcher: failed to decrypt token: {}", e);
                        None
                    }
                }
            }
            Err(_) => None
        }
    }

    /// Checks if the token has changed and updates it if necessary
    fn check_and_update_token(&self) {
        let new_token = self.read_and_decrypt_token();
        
        let mut current = self.current_token.lock().unwrap();
        
        if *current != new_token {
            match (&*current, &new_token) {
                (None, Some(token)) => {
                    log::info!("token watcher: first token received");
                    self.emit_token_to_frontend(token);
                }
                (Some(_), Some(token)) => {
                    log::info!("token watcher: token refreshed");
                    self.emit_token_to_frontend(token);
                }
                _ => {}
            }
            *current = new_token;
            self.token_changed.notify_waiters();
        }
    }
    
    /// Emits the token to the frontend via Tauri events
    fn emit_token_to_frontend(&self, token: &str) {
        let event = TokenUpdateEvent {
            token: token.to_string(),
        };
        
        match self.app_handle.emit("token-update", event) {
            Ok(_) => log::debug!("token watcher: token emitted to frontend"),
            Err(e) => log::error!("token watcher: failed to emit token-update event: {}", e),
        }
    }
}
