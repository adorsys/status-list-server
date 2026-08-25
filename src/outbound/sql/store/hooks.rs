/// Lets a contention test hold a transaction open at a chosen point so a second
/// writer provably collides with it, rather than with an already-committed row.
#[cfg(test)]
pub(crate) mod snapshot_txn_test_hook {
    use std::sync::OnceLock;
    use tokio::sync::{Mutex, oneshot};

    pub(crate) struct Probe {
        pub(crate) list_id: String,
        pub(crate) ready: oneshot::Sender<()>,
        pub(crate) release: oneshot::Receiver<()>,
    }

    pub(crate) struct PauseSite {
        slot: OnceLock<Mutex<Option<Probe>>>,
    }

    impl PauseSite {
        const fn new() -> Self {
            Self {
                slot: OnceLock::new(),
            }
        }

        fn slot(&self) -> &Mutex<Option<Probe>> {
            self.slot.get_or_init(|| Mutex::new(None))
        }

        #[cfg(any(feature = "mysql", feature = "postgres-tests"))]
        pub(crate) async fn install(&self, probe_to_install: Probe) {
            let mut guard = self.slot().lock().await;
            assert!(
                guard.is_none(),
                "only one contention probe can be installed at a time"
            );
            *guard = Some(probe_to_install);
        }

        pub(crate) async fn pause(&self, list_id: &str) {
            let installed_probe = {
                let mut guard = self.slot().lock().await;
                if guard
                    .as_ref()
                    .is_some_and(|installed| installed.list_id == list_id)
                {
                    guard.take()
                } else {
                    None
                }
            };

            if let Some(installed_probe) = installed_probe {
                let _ = installed_probe.ready.send(());
                let _ = installed_probe.release.await;
            }
        }
    }

    pub(crate) static UPDATE_BEFORE_COMMIT: PauseSite = PauseSite::new();
    pub(crate) static INSERT_BEFORE_COMMIT: PauseSite = PauseSite::new();
}
