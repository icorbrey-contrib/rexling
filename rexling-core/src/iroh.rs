//! Holds this device's iroh identity, its joined issuers and the runtime
//! that iroh endpoints run on, for use by rex-iroh.
//!
//! The caller supplies the device key, so a platform keystore can hold it.
//! This module never writes the key to a file.

use std::{path::PathBuf, sync::OnceLock};

use anyhow::{Context, Result, anyhow};
use iroh::{EndpointId, SecretKey};
use rex_iroh::joined::{Joined, Listing};

/// The runtime every iroh endpoint and its background tasks run on.
///
/// Callers keep their own short-lived runtimes, so an endpoint cannot live on
/// one of them: it would stop when that runtime does. This one lives for the
/// whole process. Do not call `block_on` on it from code that already runs on
/// a Tokio runtime. Spawn the work and await the handle instead.
///
/// Building it can fail, for example when the OS refuses a thread. The error
/// is returned, and the next call tries again.
pub fn runtime() -> Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<std::result::Result<tokio::runtime::Runtime, String>> =
        OnceLock::new();

    let built = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("rex-iroh")
            .enable_all()
            .build()
            .map_err(|error| error.to_string())
    });
    built
        .as_ref()
        .map_err(|message| anyhow!("starting the iroh runtime: {message}"))
}

/// What the caller supplies to start this device's iroh state. It has no
/// `Debug` implementation, so the secret key is never printed.
pub struct Config {
    /// The directory for the joined-issuer files, in `peers/` and the connect
    /// sockets, in `sockets/`. Use an absolute path. This module never
    /// writes the device key here.
    pub state_dir: PathBuf,

    /// This device's secret key. Its public half is the device's endpoint id.
    pub secret_key: SecretKey,
}

/// This device's identity and the issuers it has joined.
pub struct Service {
    id: EndpointId,
    joined: Joined,
}

impl Service {
    /// Prepare the state. Nothing binds a network socket here.
    pub fn new(config: Config) -> Result<Self> {
        let id = config.secret_key.public();
        let joined = Joined::new(
            config.state_dir.join("peers"),
            config.state_dir.join("sockets"),
            id,
        );
        Ok(Self { id, joined })
    }

    /// This device's endpoint id.
    pub fn id(&self) -> EndpointId {
        self.id
    }

    /// The issuers this device has joined, and the joined files that could
    /// not be read. One unreadable file does not hide the others.
    pub fn issuers(&self) -> Result<Listing> {
        self.joined.list().context("reading joined issuers")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn config(dir: &std::path::Path) -> Config {
        Config {
            state_dir: dir.to_path_buf(),
            secret_key: SecretKey::from_bytes(&[7; 32]),
        }
    }

    #[test]
    fn identity_comes_from_the_supplied_key() {
        let dir = tempfile::tempdir().unwrap();
        let service = Service::new(config(dir.path())).unwrap();

        assert_eq!(service.id(), SecretKey::from_bytes(&[7; 32]).public());
        let listing = service.issuers().unwrap();
        assert!(listing.issuers.is_empty() && listing.unreadable.is_empty());
    }

    #[test]
    fn a_corrupt_joined_file_is_listed_beside_the_readable_issuers() {
        let dir = tempfile::tempdir().unwrap();
        let peers = dir.path().join("peers");
        std::fs::create_dir_all(&peers).unwrap();
        std::fs::write(peers.join("broken"), b"not a ticket").unwrap();
        let service = Service::new(config(dir.path())).unwrap();

        let listing = service.issuers().unwrap();
        assert!(listing.issuers.is_empty());
        assert_eq!(listing.unreadable.len(), 1);
        assert!(listing.unreadable[0].path().ends_with("broken"));
    }

    #[test]
    fn runtime_has_two_workers() {
        assert_eq!(runtime().unwrap().metrics().num_workers(), 2);
    }

    #[test]
    fn a_task_on_the_shared_runtime_outlives_the_runtime_that_spawned_it() {
        let caller = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let handle = caller.block_on(std::future::ready(runtime().unwrap().spawn(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            42
        })));
        drop(caller);

        assert_eq!(runtime().unwrap().block_on(handle).unwrap(), 42);
    }
}
