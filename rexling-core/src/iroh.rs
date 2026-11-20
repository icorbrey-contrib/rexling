//! Holds this device's iroh identity, its joined issuers and the runtime
//! that iroh endpoints run on, for use by rex-iroh.
//!
//! The caller supplies the device key, so a platform keystore can hold it.
//! This module never writes the key to a file.

use std::{
    collections::HashMap,
    os::unix::net::UnixStream as StdUnixStream,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

use anyhow::{Context, Result, anyhow};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey};
use rex_iroh::{
    joined::{Issuer, Joined, Listing},
    node::{Lookup, Network, Relays},
    status::LinkStatus,
    tunnel::{CloseReason, Dialer, splice},
};
use tokio::net::UnixStream;
use url::Url;

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

    /// Relay URLs to use instead of n0's. Blank entries are ignored, and an
    /// empty list means n0's relays.
    pub relays: Vec<String>,

    /// A pkarr relay URL for publishing and looking up addresses. A blank
    /// value or `None` means n0's DNS server.
    pub address_lookup: Option<String>,
}

/// Builds the network settings from the caller's text, so blank fields mean
/// n0's defaults in one place.
fn network(relays: &[String], address_lookup: Option<&str>) -> Result<Network> {
    let relays = relays
        .iter()
        .map(|relay| relay.trim())
        .filter(|relay| !relay.is_empty())
        .map(|relay| {
            relay
                .parse::<RelayUrl>()
                .with_context(|| format!("relay URL {relay:?}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let lookup = match address_lookup.map(str::trim).filter(|url| !url.is_empty()) {
        None => Lookup::N0,
        Some(url) => Lookup::Pkarr(
            Url::parse(url).with_context(|| format!("address lookup URL {url:?}"))?,
        ),
    };

    Ok(Network {
        relays: Relays::from_urls(relays),
        lookup,
    })
}

/// One joined issuer and how its connection stands. The link state keeps
/// rex-iroh's serializable shape, so the app can encode it as JSON.
pub struct IssuerStatus {
    pub name: String,
    pub id: EndpointId,
    pub link: LinkStatus,

    /// Set while the issuer turns this device away.
    pub refused: Option<CloseReason>,
}

/// This device's identity, its network settings and the issuers it has
/// joined.
pub struct Service {
    id: EndpointId,
    secret: SecretKey,
    network: Network,
    joined: Joined,

    /// Bound on first use, so reading the state never touches the network.
    endpoint: tokio::sync::OnceCell<Endpoint>,

    /// One dialer per issuer, kept with the address it dials, so a re-paired
    /// issuer with a new address gets a new dialer.
    dialers: Mutex<HashMap<EndpointId, (EndpointAddr, Arc<Dialer>)>>,
}

impl Service {
    /// Prepare the state. Nothing binds a network socket here.
    pub fn new(config: Config) -> Result<Self> {
        let id = config.secret_key.public();
        let network = network(&config.relays, config.address_lookup.as_deref())?;
        let joined = Joined::new(
            config.state_dir.join("peers"),
            config.state_dir.join("sockets"),
            id,
        );

        Ok(Self {
            id,
            secret: config.secret_key,
            network,
            joined,
            endpoint: tokio::sync::OnceCell::new(),
            dialers: Mutex::new(HashMap::new()),
        })
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

    /// Open a byte stream to the Rex socket behind issuer `id`.
    ///
    /// The stream is an ordinary Unix socket on the caller's runtime, so the
    /// caller reads and writes it like any local socket. Errors name the
    /// issuer, and say so when the issuer turned this device away.
    pub async fn connect(self: &Arc<Self>, id: EndpointId) -> Result<UnixStream> {
        let service = self.clone();
        let local = runtime()?
            .spawn(async move { service.tunnel(id).await })
            .await
            .context("the iroh runtime stopped")??;

        // Converted here, after the hand-off, so the socket registers with
        // the caller's runtime rather than the iroh one.
        local.set_nonblocking(true)?;
        Ok(UnixStream::from_std(local)?)
    }

    /// Start the tunnel to issuer `id` and return the far end of a local
    /// socket pair. Runs on the iroh runtime.
    async fn tunnel(self: Arc<Self>, id: EndpointId) -> Result<StdUnixStream> {
        let endpoint = self.endpoint().await?;
        let issuer = self
            .issuers()?
            .issuers
            .into_iter()
            .find(|issuer| issuer.id() == id)
            .ok_or_else(|| anyhow!("no joined issuer has endpoint id {id}"))?;
        let dialer = self.dialer(&endpoint, &issuer)?;

        let (send, recv) = match dialer.open_bi().await {
            Ok(streams) => streams,
            Err(error) => {
                return Err(match dialer.refusal() {
                    Some(refused) => anyhow!("issuer {id} turned this device away: {refused}"),
                    None => anyhow::Error::new(error).context(format!("reaching issuer {id}")),
                });
            }
        };

        let (near, far) = StdUnixStream::pair()?;
        near.set_nonblocking(true)?;
        let near = UnixStream::from_std(near)?;

        // The tunnel ends when either side closes; its errors end it the
        // same way, so nothing is left to report them to.
        tokio::spawn(async move {
            splice(send, recv, near).await.ok();
        });

        Ok(far)
    }

    /// Tell the endpoint the network changed, so it re-checks its paths.
    /// Does nothing before the endpoint is bound.
    pub async fn network_change(&self) -> Result<()> {
        let Some(endpoint) = self.endpoint.get().cloned() else {
            return Ok(());
        };
        runtime()?
            .spawn(async move { endpoint.network_change().await })
            .await
            .context("the iroh runtime stopped")
    }

    /// The endpoint with this device's key, bound on the first call.
    async fn endpoint(&self) -> Result<Endpoint> {
        let endpoint = self
            .endpoint
            .get_or_try_init(|| async {
                self.network
                    .clone()
                    .endpoint_builder(self.secret.clone())
                    .bind()
                    .await
                    .context("binding the iroh endpoint")
            })
            .await?;
        Ok(endpoint.clone())
    }

    /// Each joined issuer with its connection state. An issuer that has not
    /// been dialed yet reports idle; the endpoint is not bound by this call.
    pub fn issuer_status(&self) -> Result<Vec<IssuerStatus>> {
        let dialers = self
            .dialers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        Ok(self
            .issuers()?
            .issuers
            .into_iter()
            .map(|issuer| {
                let id = issuer.id();
                match dialers.get(&id) {
                    Some((_, dialer)) => IssuerStatus {
                        name: issuer.name.to_string(),
                        id,
                        link: dialer.link(),
                        refused: dialer.refusal().map(|refused| refused.reason()),
                    },
                    None => IssuerStatus {
                        name: issuer.name.to_string(),
                        id,
                        link: LinkStatus::Idle,
                        refused: None,
                    },
                }
            })
            .collect())
    }

    /// The dialer for `issuer`, made on first use and reused after.
    fn dialer(&self, endpoint: &Endpoint, issuer: &Issuer) -> Result<Arc<Dialer>> {
        let addr = issuer.ticket.endpoint_addr().clone();
        let mut dialers = self
            .dialers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some((_, dialer)) = dialers.get(&issuer.id()).filter(|(known, _)| *known == addr) {
            return Ok(dialer.clone());
        }

        let dialer = Arc::new(
            Dialer::new(endpoint.clone(), addr.clone())
                .with_context(|| format!("dialing issuer {}", issuer.name))?,
        );
        dialers.insert(issuer.id(), (addr, dialer.clone()));
        Ok(dialer)
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
            relays: Vec::new(),
            address_lookup: None,
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
    fn empty_and_blank_settings_mean_n0() {
        let blank = vec!["  ".to_string(), String::new()];
        let network = network(&blank, Some("   ")).unwrap();

        assert_eq!(network.relays, Relays::N0);
        assert_eq!(network.lookup, Lookup::N0);
    }

    #[test]
    fn relay_urls_become_the_only_relays() {
        let url = "https://relay.example.test/".to_string();
        let network = network(std::slice::from_ref(&url), None).unwrap();

        let expected: RelayUrl = url.parse().unwrap();
        assert_eq!(network.relays, Relays::Only(vec![expected]));
    }

    #[test]
    fn an_address_lookup_url_becomes_pkarr() {
        let url = "https://pkarr.example.test/pkarr";
        let network = network(&[], Some(url)).unwrap();

        assert_eq!(network.lookup, Lookup::Pkarr(Url::parse(url).unwrap()));
    }

    #[test]
    fn a_bad_address_lookup_url_is_named_in_the_error() {
        let Err(error) = network(&[], Some("not a url")) else {
            panic!("a bad URL fails");
        };
        assert!(format!("{error:#}").contains("not a url"), "{error:#}");
    }

    #[test]
    fn a_bad_relay_url_is_named_in_the_error() {
        let Err(error) = network(&["not a url".to_string()], None) else {
            panic!("a bad relay fails");
        };
        assert!(format!("{error:#}").contains("not a url"), "{error:#}");
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
