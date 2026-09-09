use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher as _};
use std::collections::{HashMap, HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc as std_mpsc};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::Instant;

const DEBOUNCE: Duration = Duration::from_millis(500);
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub(crate) struct FileWatcher {
    paths: Arc<Vec<PathBuf>>,
    poll_interval: Duration,
}

impl FileWatcher {
    /// Create a watcher for a set of paths. Duplicate paths are ignored and the
    /// fallback poll interval is clamped to at least one second.
    pub(crate) fn new(paths: Vec<PathBuf>, poll_interval: Duration) -> Self {
        let mut unique = HashSet::new();
        let paths = paths
            .into_iter()
            .filter(|path| unique.insert(path.clone()))
            .collect();
        let poll_interval = if poll_interval < MIN_POLL_INTERVAL {
            tracing::debug!(
                configured_secs = poll_interval.as_secs_f64(),
                minimum_secs = MIN_POLL_INTERVAL.as_secs_f64(),
                "file watcher poll interval below minimum; clamping"
            );
            MIN_POLL_INTERVAL
        } else {
            poll_interval
        };
        Self {
            paths: Arc::new(paths),
            poll_interval,
        }
    }

    /// Spawn background watching with 500ms debouncing. The callback runs
    /// serially, so a later change waits for any in-flight reload to finish.
    pub(crate) fn spawn<F, Fut>(self, target: &'static str, on_change: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let callback = Arc::new(on_change);
        let paths = self.paths.clone();
        let (tx, rx) = mpsc::channel(32);

        let native_started = spawn_notify_watcher(paths.clone(), tx.clone(), target);
        if !native_started {
            spawn_poll_watcher(paths.clone(), tx, target, self.poll_interval);
        }
        spawn_debouncer(paths, rx, callback, target);
    }
}

fn spawn_notify_watcher(
    paths: Arc<Vec<PathBuf>>,
    tx: mpsc::Sender<()>,
    target: &'static str,
) -> bool {
    let (started_tx, started_rx) = std_mpsc::sync_channel(1);
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
                    "native file watcher could not start; falling back to polling"
                );
                let _ = started_tx.send(false);
                return;
            }
        };

        let mut all_watched = true;
        for watched in watch_roots(&paths) {
            if let Err(err) = watcher.watch(&watched, RecursiveMode::NonRecursive) {
                all_watched = false;
                tracing::warn!(
                    event = "file_watcher_path_unavailable",
                    rotation.target = target,
                    path = %watched.display(),
                    error = %err,
                    "file watcher could not watch path; falling back to polling"
                );
            }
        }

        let _ = started_tx.send(all_watched);
        if !all_watched {
            return;
        }

        // Keep the notify watcher in scope for the process lifetime. File
        // watchers are installed once during startup for long-lived credentials.
        loop {
            std::thread::park();
        }
    });

    started_rx.recv().unwrap_or(false)
}

fn spawn_poll_watcher(
    paths: Arc<Vec<PathBuf>>,
    tx: mpsc::Sender<()>,
    target: &'static str,
    poll_interval: Duration,
) {
    tokio::spawn(async move {
        let mut fingerprints = fingerprint_all(&paths).await;
        let mut interval = tokio::time::interval_at(Instant::now() + poll_interval, poll_interval);
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
            callback().await;
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
        || (changed.file_name().is_some_and(|name| name == "..data")
            && changed.parent() == watched.parent())
}

async fn fingerprint_all(paths: &[PathBuf]) -> HashMap<PathBuf, Option<u64>> {
    let mut tasks = JoinSet::new();
    for path in paths {
        let path = path.clone();
        tasks.spawn(async move {
            let fingerprint = fingerprint(&path).await;
            (path, fingerprint)
        });
    }

    let mut fingerprints = HashMap::with_capacity(paths.len());
    while let Some(result) = tasks.join_next().await {
        if let Ok((path, fingerprint)) = result {
            fingerprints.insert(path, fingerprint);
        }
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
    use tokio::time::timeout;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "status-list-watcher-test-{}-{}",
                std::process::id(),
                time::OffsetDateTime::now_utc().unix_timestamp_nanos()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            let path = std::fs::canonicalize(&path).unwrap_or(path);
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

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

    #[tokio::test]
    async fn debouncer_serializes_callbacks() {
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel(8);
        let paths = Arc::new(vec![PathBuf::from("/tmp/secret")]);

        spawn_debouncer(
            paths,
            rx,
            Arc::new({
                let active = active.clone();
                let max_active = max_active.clone();
                let completed = completed.clone();
                move || {
                    let active = active.clone();
                    let max_active = max_active.clone();
                    let completed = completed.clone();
                    async move {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        max_active.fetch_max(current, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        completed.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }),
            "test",
        );

        tx.send(()).await.expect("first event");
        tokio::time::sleep(DEBOUNCE + Duration::from_millis(50)).await;
        tx.send(()).await.expect("second event");
        tokio::time::sleep(DEBOUNCE + Duration::from_millis(500)).await;

        assert_eq!(max_active.load(Ordering::SeqCst), 1);
        assert_eq!(completed.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn k8s_data_symlink_events_only_match_same_directory() {
        assert!(path_relevant(
            Path::new("/var/run/secrets/db/..data"),
            Path::new("/var/run/secrets/db/password")
        ));
        assert!(!path_relevant(
            Path::new("/var/run/secrets/other/..data"),
            Path::new("/var/run/secrets/db/password")
        ));
        assert!(!path_relevant(
            Path::new("/var/run/secrets/db/unrelated"),
            Path::new("/var/run/secrets/db/password")
        ));
    }

    #[tokio::test]
    async fn spawn_dispatches_callback_after_file_write() {
        let dir = TempDir::new();
        let path = dir.path.join("secret");
        tokio::fs::write(&path, "first")
            .await
            .expect("write initial");

        let (tx, mut rx) = mpsc::channel(1);
        FileWatcher::new(vec![path.clone()], Duration::from_secs(1)).spawn("test", move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(()).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        tokio::fs::write(&path, "second")
            .await
            .expect("write update");
        timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("watcher callback timed out")
            .expect("watcher callback");
    }
}
