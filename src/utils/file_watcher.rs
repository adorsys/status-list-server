use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher as _};
use std::collections::{HashMap, HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const DEBOUNCE: Duration = Duration::from_millis(500);

#[derive(Debug)]
pub(crate) struct FileWatcher {
    paths: Arc<Vec<PathBuf>>,
    poll_interval: Duration,
}

impl FileWatcher {
    pub(crate) fn new(paths: Vec<PathBuf>, poll_interval: Duration) -> Self {
        let mut unique = HashSet::new();
        let paths = paths
            .into_iter()
            .filter(|path| unique.insert(path.clone()))
            .collect();
        Self {
            paths: Arc::new(paths),
            poll_interval: poll_interval.max(Duration::from_secs(1)),
        }
    }

    pub(crate) fn spawn<F, Fut>(self, target: &'static str, on_change: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let callback = Arc::new(on_change);
        let paths = self.paths.clone();
        let (tx, rx) = mpsc::channel(32);

        spawn_notify_watcher(paths.clone(), tx.clone(), target);
        spawn_poll_watcher(paths.clone(), tx, target, self.poll_interval);
        spawn_debouncer(paths, rx, callback, target);
    }
}

fn spawn_notify_watcher(paths: Arc<Vec<PathBuf>>, tx: mpsc::Sender<()>, target: &'static str) {
    std::thread::spawn(move || {
        let tx_events = tx.clone();
        let event_paths = paths.clone();
        let mut watcher = match RecommendedWatcher::new(
            move |event: notify::Result<Event>| match event {
                Ok(event) => {
                    if event_matches(&event, &event_paths) {
                        let _ = tx_events.blocking_send(());
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        event = "file_watcher_error",
                        rotation.target = target,
                        error = %err,
                        "file watcher backend reported an error"
                    );
                }
            },
            notify::Config::default(),
        ) {
            Ok(watcher) => watcher,
            Err(err) => {
                tracing::warn!(
                    event = "file_watcher_fallback_polling",
                    rotation.target = target,
                    error = %err,
                    "native file watcher could not start; polling remains active"
                );
                return;
            }
        };

        for watched in watch_roots(&paths) {
            if let Err(err) = watcher.watch(&watched, RecursiveMode::NonRecursive) {
                tracing::warn!(
                    event = "file_watcher_path_unavailable",
                    rotation.target = target,
                    path = %watched.display(),
                    error = %err,
                    "file watcher could not watch path; polling remains active"
                );
            }
        }

        loop {
            std::thread::park();
        }
    });
}

fn spawn_poll_watcher(
    paths: Arc<Vec<PathBuf>>,
    tx: mpsc::Sender<()>,
    target: &'static str,
    poll_interval: Duration,
) {
    tokio::spawn(async move {
        let mut fingerprints = fingerprint_all(&paths).await;
        let mut interval = tokio::time::interval(poll_interval);
        loop {
            interval.tick().await;
            let next = fingerprint_all(&paths).await;
            if next != fingerprints {
                fingerprints = next;
                tracing::info!(
                    event = "file_change_detected",
                    rotation.target = target,
                    source = "poll",
                    "watched secret file changed"
                );
                if tx.send(()).await.is_err() {
                    break;
                }
            }
        }
    });
}

fn spawn_debouncer<F, Fut>(
    paths: Arc<Vec<PathBuf>>,
    mut rx: mpsc::Receiver<()>,
    callback: Arc<F>,
    target: &'static str,
) where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            tracing::info!(
                event = "file_change_detected",
                rotation.target = target,
                paths = ?paths,
                "watched secret file changed"
            );
            while matches!(tokio::time::timeout(DEBOUNCE, rx.recv()).await, Ok(Some(_))) {}
            let callback = callback.clone();
            tokio::spawn(async move {
                callback().await;
            });
        }
    });
}

fn watch_roots(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut unique = HashSet::new();
    let mut roots = Vec::new();
    for path in paths {
        for root in [Some(path.as_path()), path.parent()] {
            if let Some(root) = root
                && unique.insert(root.to_path_buf())
            {
                roots.push(root.to_path_buf());
            }
        }
    }
    roots
}

fn event_matches(event: &Event, watched_paths: &[PathBuf]) -> bool {
    event.paths.iter().any(|changed| {
        watched_paths
            .iter()
            .any(|watched| path_relevant(changed, watched))
    })
}

fn path_relevant(changed: &Path, watched: &Path) -> bool {
    changed == watched
        || changed.starts_with(watched)
        || watched.starts_with(changed)
        || changed.file_name().is_some_and(|name| name == "..data")
        || changed
            .parent()
            .is_some_and(|parent| watched.parent() == Some(parent))
}

async fn fingerprint_all(paths: &[PathBuf]) -> HashMap<PathBuf, Option<u64>> {
    let mut fingerprints = HashMap::new();
    for path in paths {
        fingerprints.insert(path.clone(), fingerprint(path).await);
    }
    fingerprints
}

async fn fingerprint(path: &Path) -> Option<u64> {
    let bytes = tokio::fs::read(path).await.ok()?;
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    Some(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn debouncer_coalesces_bursty_changes() {
        let rotations = Arc::new(AtomicUsize::new(0));
        let seen = rotations.clone();
        let (tx, rx) = mpsc::channel(8);
        let paths = Arc::new(vec![PathBuf::from("/tmp/secret")]);

        spawn_debouncer(
            paths,
            rx,
            Arc::new(move || {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                }
            }),
            "test",
        );

        tx.send(()).await.expect("first event");
        tx.send(()).await.expect("second event");
        tokio::time::sleep(Duration::from_millis(700)).await;

        assert_eq!(rotations.load(Ordering::SeqCst), 1);
    }
}
