//! The iroh module against an issuer running in this process. The issuer is
//! rex-iroh's own server side on loopback, in front of a stub Rex socket. The
//! device's relay and address-lookup URLs point at a closed loopback port,
//! so nothing touches n0's servers and every dial goes direct.
#![cfg(feature = "iroh")]

use std::{path::PathBuf, sync::Arc, time::Duration};

use iroh::{
    Endpoint, EndpointId, SecretKey,
    endpoint::presets,
    protocol::Router,
};
use iroh_tickets::endpoint::EndpointTicket;
use rex_iroh::{
    allowlist,
    joined::Joined,
    tunnel::{ALPN, RexBridge},
};
use rexling_core::iroh::{Config, Service};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

/// A loopback port nothing listens on. Relay and lookup stay unreachable, so
/// only the direct addresses in the issuer's ticket carry the dial.
const UNREACHABLE: &str = "http://127.0.0.1:9/";

async fn within<T>(what: &str, fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), fut)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

async fn loopback(key: SecretKey) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap()
}

/// A rex-iroh issuer: a tunnel to a stub Rex socket that echoes each
/// connection's request back after `echo:`, allowing `allowed` devices.
struct Issuer {
    endpoint: Endpoint,
    _router: Router,
    _dir: tempfile::TempDir,
}

impl Issuer {
    async fn start(allowed: &[EndpointId]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let rex_socket = dir.path().join("rex.sock");
        let listener = UnixListener::bind(&rex_socket).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    if stream.read_to_end(&mut request).await.is_ok() {
                        stream.write_all(b"echo:").await.ok();
                        stream.write_all(&request).await.ok();
                        stream.shutdown().await.ok();
                    }
                });
            }
        });

        let list = dir.path().join("allowlist");
        for id in allowed {
            allowlist::add(&list, id, "test").unwrap();
        }

        let endpoint = loopback(SecretKey::generate()).await;
        let bridge = RexBridge::new(list, rex_socket);
        let router = Router::builder(endpoint.clone())
            .accept(ALPN, bridge)
            .spawn();

        Self {
            endpoint,
            _router: router,
            _dir: dir,
        }
    }

    fn ticket(&self) -> EndpointTicket {
        EndpointTicket::new(self.endpoint.addr())
    }
}

/// A device with its own state directory, and the iroh service it runs.
struct Device {
    service: Arc<Service>,
    secret: SecretKey,
    state: PathBuf,
    _dir: tempfile::TempDir,
}

impl Device {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let secret = SecretKey::generate();
        let service = Service::new(Config {
            state_dir: state.clone(),
            secret_key: secret.clone(),
            relays: vec![UNREACHABLE.into()],
            address_lookup: Some(format!("{UNREACHABLE}pkarr")),
        })
        .unwrap();

        Self {
            service: Arc::new(service),
            secret,
            state,
            _dir: dir,
        }
    }

    /// Record `issuer` as joined, as a completed pairing would.
    fn join(&self, issuer: &Issuer) {
        let joined = Joined::new(
            self.state.join("peers"),
            self.state.join("sockets"),
            self.service.id(),
        );
        let claim = joined
            .claim(None, issuer.endpoint.id())
            .unwrap()
            .expect("the name is free");
        joined.save(claim, &issuer.ticket()).unwrap();
    }
}

#[tokio::test]
async fn connect_reaches_the_rex_socket_through_an_allowed_issuer() {
    let device = Device::new();
    let issuer = Issuer::start(&[device.service.id()]).await;
    device.join(&issuer);

    let echoed = within("the echo", async {
        let mut stream = device.service.connect(issuer.endpoint.id()).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        reply
    })
    .await;

    assert_eq!(echoed, b"echo:hello");
}

/// Every file under `dir`, recursively.
fn files_under(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(files_under(&path));
        } else {
            found.push(path);
        }
    }
    found
}

#[tokio::test]
async fn the_device_key_never_reaches_disk() {
    let device = Device::new();
    let issuer = Issuer::start(&[device.service.id()]).await;
    device.join(&issuer);
    let mut stream = device.service.connect(issuer.endpoint.id()).await.unwrap();
    stream.shutdown().await.ok();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.ok();

    let key = device.secret.to_bytes();
    let files = files_under(device._dir.path());
    assert!(!files.is_empty(), "the state directory has files to check");
    for file in files {
        let bytes = std::fs::read(&file).unwrap();
        assert!(
            !bytes.windows(key.len()).any(|window| window == key),
            "{} holds the device key",
            file.display()
        );
    }
}

#[tokio::test]
async fn connect_names_an_endpoint_id_that_is_not_joined() {
    let device = Device::new();
    let stranger = SecretKey::generate().public();

    let Err(error) = device.service.connect(stranger).await else {
        panic!("an unjoined id fails");
    };

    assert!(
        format!("{error:#}").contains(&format!("no joined issuer has endpoint id {stranger}")),
        "unexpected error: {error:#}"
    );
}

#[tokio::test]
async fn a_device_off_the_allowlist_gets_no_reply() {
    let device = Device::new();
    let issuer = Issuer::start(&[]).await;
    device.join(&issuer);

    // The issuer closes the connection as it accepts it, so the stream
    // either fails to open or ends without the echo. Either way no reply
    // from Rex reaches the device.
    let reply = within("the refused attempt", async {
        match device.service.connect(issuer.endpoint.id()).await {
            Err(error) => Err(error.to_string()),
            Ok(mut stream) => {
                stream.write_all(b"hello").await.ok();
                stream.shutdown().await.ok();
                let mut reply = Vec::new();
                match stream.read_to_end(&mut reply).await {
                    Ok(_) => Ok(reply),
                    Err(error) => Err(error.to_string()),
                }
            }
        }
    })
    .await;

    assert!(
        reply.as_ref().map_or(true, |bytes| bytes.is_empty()),
        "refused device got a reply: {reply:?}"
    );
}
