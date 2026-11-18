//! Persistent custom blocklist (JSON on disk), mirroring `blocklist.py`.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fc_shared::config::Config;

/// Shared blocklist store: in-memory set with load/save to disk.
pub struct Blocklist {
    path: PathBuf,
    inner: Mutex<BTreeSet<String>>,
}

impl Blocklist {
    pub fn new(data_dir: PathBuf) -> Self {
        let path = data_dir.join("blocklist.json");
        let words = Self::load(&path);
        Self {
            path,
            inner: Mutex::new(words),
        }
    }

    fn load(path: &PathBuf) -> BTreeSet<String> {
        match std::fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str::<Vec<String>>(&text) {
                Ok(list) => Self::normalize(list.into_iter()),
                Err(_) => BTreeSet::new(),
            },
            Err(_) => BTreeSet::new(),
        }
    }

    fn normalize<I: IntoIterator<Item = String>>(iter: I) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for raw in iter {
            if raw.trim().is_empty() {
                continue;
            }
            // Collapse whitespace runs to single space, lowercase.
            let cleaned = raw.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
            if !cleaned.is_empty() {
                out.insert(cleaned);
            }
        }
        out
    }

    fn save(&self, words: &BTreeSet<String>) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let list: Vec<String> = words.iter().cloned().collect();
        if let Ok(text) = serde_json::to_string_pretty(&list) {
            let _ = std::fs::write(&self.path, text);
        }
    }

    /// Current sorted blocklist.
    pub fn get_blocklist(&self) -> Vec<String> {
        self.inner.lock().expect("blocklist lock").iter().cloned().collect()
    }

    /// Add words; returns (added, updated_list).
    pub fn add_words(&self, words: Vec<String>) -> (Vec<String>, Vec<String>) {
        let normalized = Self::normalize(words);
        if normalized.is_empty() {
            return (vec![], self.get_blocklist());
        }
        let mut guard = self.inner.lock().expect("blocklist lock");
        let added: Vec<String> = normalized.difference(&*guard).cloned().collect();
        if added.is_empty() {
            return (vec![], guard.iter().cloned().collect());
        }
        let updated: BTreeSet<String> = guard.union(&normalized).cloned().collect();
        *guard = updated.clone();
        self.save(&updated);
        (added, updated.into_iter().collect())
    }

    /// Remove words; returns (removed, updated_list).
    pub fn remove_words(&self, words: Vec<String>) -> (Vec<String>, Vec<String>) {
        let normalized = Self::normalize(words);
        if normalized.is_empty() {
            return (vec![], self.get_blocklist());
        }
        let mut guard = self.inner.lock().expect("blocklist lock");
        let removed: Vec<String> = normalized.intersection(&*guard).cloned().collect();
        if removed.is_empty() {
            return (vec![], guard.iter().cloned().collect());
        }
        let updated: BTreeSet<String> = guard.difference(&normalized).cloned().collect();
        *guard = updated.clone();
        self.save(&updated);
        (removed, updated.into_iter().collect())
    }

    pub fn clear_blocklist(&self) {
        let mut guard = self.inner.lock().expect("blocklist lock");
        guard.clear();
        self.save(&guard);
    }
}

/// Application state wrapper shared across handlers.
#[derive(Clone)]
pub struct State {
    pub blocklist: Arc<Blocklist>,
}

impl State {
    pub fn new(config: &Config) -> Self {
        let data_dir = if config.files_dir.to_string_lossy().is_empty() {
            std::path::PathBuf::from("/data")
        } else {
            // chat_filter uses DATA_DIR; fall back to /data.
            std::path::PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "/data".to_string()))
        };
        Self {
            blocklist: Arc::new(Blocklist::new(data_dir)),
        }
    }
}