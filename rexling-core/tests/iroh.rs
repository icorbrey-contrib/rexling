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
    invite::Invite,
    joined::Joined,
    pair::{
        ALPN as PAIR_ALPN, Approver, Decision, INVITE_LIFETIME, InviteStore, Outcome,
        PairHandler, PairingRequest, Policy, SystemClock, Timeouts,
    },
    sas::Sas,
    tunnel::{ALPN, RexBridge},
};
use rexling_core::{
    iroh::{Config, PairingState, Service},
    transport::{CONTROL, Endpoint as RexEndpoint, IROH_SCHEME},
};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

/// A loopback port nothing listens on. Relay and lookup stay unreachable, so
/// only the direct addresses in the issuer's ticket carry the dial.
const UNREACHABLE: &str = "http://127.0.0.1:9/";

/// Answers the control WebSocket handshake, then `pong:` to each text message.
async fn serve_control(stream: UnixStream) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::{
            Message,
            handshake::server::{Request, Response},
        },
    };

    #[allow(clippy::result_large_err)]
    let mut socket = accept_hdr_async(stream, |request: &Request, mut response: Response| {
        assert_eq!(request.headers()["Sec-WebSocket-Protocol"], CONTROL);
        response
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", CONTROL.parse().unwrap());
        Ok(response)
    })
    .await
    .unwrap();

    while let Some(Ok(message)) = socket.next().await {
        if let Message::Text(text) = message {
            socket
                .send(Message::Text(format!("pong:{text}").into()))
                .await
                .ok();
        }
    }
}

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

/// What the stub Rex socket speaks.
#[derive(Clone, Copy)]
enum Rex {
    /// Raw bytes: each connection's request comes back after `echo:`.
    Echo,

    /// The control WebSocket: it answers each text message with `pong:`.
    WebSocket,
}

impl Issuer {
    async fn start(allowed: &[EndpointId]) -> Self {
        Self::start_as(allowed, Rex::Echo).await
    }

    async fn start_as(allowed: &[EndpointId], rex: Rex) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let rex_socket = dir.path().join("rex.sock");
        let listener = UnixListener::bind(&rex_socket).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    match rex {
                        Rex::Echo => {
                            let mut request = Vec::new();
                            if stream.read_to_end(&mut request).await.is_ok() {
                                stream.write_all(b"echo:").await.ok();
                                stream.write_all(&request).await.ok();
                                stream.shutdown().await.ok();
                            }
                        }
                        Rex::WebSocket => serve_control(stream).await,
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

#[tokio::test]
async fn status_reports_idle_then_connected_then_refused() {
    let device = Device::new();
    let welcome = Issuer::start(&[device.service.id()]).await;
    let refuser = Issuer::start(&[]).await;
    device.join(&welcome);
    device.join(&refuser);

    let before = device.service.issuer_status().unwrap();
    assert!(before.iter().all(|s| matches!(s.link, rex_iroh::status::LinkStatus::Idle)));

    let mut stream = device.service.connect(welcome.endpoint.id()).await.unwrap();
    stream.shutdown().await.ok();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.ok();

    let refused_id = refuser.endpoint.id();
    device.service.connect(refused_id).await.ok();

    within("the refusal to be recorded", async {
        loop {
            let status = device.service.issuer_status().unwrap();
            let refused = status
                .iter()
                .find(|s| s.id == refused_id)
                .and_then(|s| s.refused);
            if refused.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    let status = device.service.issuer_status().unwrap();
    let welcome_status = status.iter().find(|s| s.id == welcome.endpoint.id()).unwrap();
    assert!(matches!(
        welcome_status.link,
        rex_iroh::status::LinkStatus::Connected { .. }
    ));
    let refused_status = status.iter().find(|s| s.id == refused_id).unwrap();
    assert_eq!(
        refused_status.refused,
        Some(rex_iroh::tunnel::CloseReason::Denied)
    );
}

/// Holds the issuer's decision until the test sends one, so the test can
/// read the words the joiner shows while the issuer is still deciding.
#[derive(Debug)]
struct Gate(std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<Decision>>>);

impl Approver for Gate {
    async fn decide(&self, _request: &PairingRequest) -> Decision {
        let decision = self.0.lock().unwrap().take().expect("one request");
        decision.await.unwrap_or(Decision::NoAnswer)
    }

    fn finished(&self, _request: &PairingRequest, _outcome: &Outcome) {}
}

/// An issuer that answers pairing requests through `gate`, and mints one
/// invite for them.
async fn prompting_issuer(gate: Gate) -> (Endpoint, Router, Invite, PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let list = dir.path().join("allowlist");
    let endpoint = loopback(SecretKey::generate()).await;
    let store = Arc::new(InviteStore::new(Arc::new(SystemClock), INVITE_LIFETIME));
    let secret = store.mint(Policy::Prompt, gate);
    let pairing = PairHandler::new(
        endpoint.id(),
        store,
        list.clone(),
        Arc::new(SystemClock),
        Timeouts::default(),
    );
    let router = Router::builder(endpoint.clone())
        .accept(PAIR_ALPN, pairing)
        .spawn();
    let invite = Invite {
        ticket: EndpointTicket::new(endpoint.addr()),
        secret,
    };
    (endpoint, router, invite, list, dir)
}

/// Poll the device's pairing until `done` accepts its state.
async fn pairing_until(
    service: &Service,
    id: u64,
    done: impl Fn(&PairingState) -> bool,
) -> PairingState {
    within("the pairing state", async {
        loop {
            let state = service.pairing_state(id).unwrap();
            if done(&state) {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
}

#[tokio::test]
async fn pairing_shows_the_words_then_saves_the_issuer_on_accept() {
    let device = Device::new();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let (issuer, _router, invite, list, _dir) =
        prompting_issuer(Gate(std::sync::Mutex::new(Some(rx)))).await;

    let text = invite.to_string();
    let id = device.service.start_pairing(&text, Some("phone".into())).unwrap();

    let waiting = pairing_until(&device.service, id, |s| {
        matches!(s, PairingState::Waiting { .. })
    })
    .await;
    let PairingState::Waiting { words, issuer: shown } = waiting else {
        unreachable!("waited for Waiting")
    };
    assert_eq!(shown, issuer.id());
    let expected = Sas::new(&invite.secret, &issuer.id(), &device.service.id()).words();
    assert_eq!(words, expected);

    tx.send(Decision::Accept).unwrap();
    let accepted = pairing_until(&device.service, id, |s| {
        !matches!(s, PairingState::Starting | PairingState::Waiting { .. })
    })
    .await;
    assert!(matches!(accepted, PairingState::Accepted { .. }), "{accepted:?}");

    let allowed = rex_iroh::allowlist::Allowlist::load(&list).unwrap();
    assert!(allowed.contains(&device.service.id()));
    let joined = device.service.issuers().unwrap();
    assert!(joined.issuers.iter().any(|i| i.id() == issuer.id()));
}

#[tokio::test]
async fn an_unreadable_invite_is_refused_before_dialing() {
    let device = Device::new();
    let Err(error) = device
        .service
        .start_pairing("rexpair:?ticket=nope&secret=nope", None)
    else {
        panic!("a bad invite fails");
    };
    assert!(format!("{error:#}").contains("reading the invite"), "{error:#}");
}

/// A rexling `Endpoint` for `rex-iroh://<id>` on `service`.
fn rex_endpoint(service: &Arc<Service>, id: EndpointId) -> RexEndpoint {
    RexEndpoint::new(&format!("{IROH_SCHEME}://{id}"), Duration::from_secs(20))
        .unwrap()
        .with_iroh(service.clone())
}

#[tokio::test]
async fn control_websocket_round_trips_through_the_issuer() {
    let device = Device::new();
    let issuer = Issuer::start_as(&[device.service.id()], Rex::WebSocket).await;
    device.join(&issuer);

    let reply = within("the control reply", async {
        let mut socket = rex_endpoint(&device.service, issuer.endpoint.id())
            .open("/", CONTROL)
            .await
            .unwrap();
        socket.send(Message::Text("ping".into())).await.unwrap();
        match socket.next().await.unwrap().unwrap() {
            Message::Text(text) => text.to_string(),
            other => panic!("unexpected frame: {other:?}"),
        }
    })
    .await;

    assert_eq!(reply, "pong:ping");
}

#[tokio::test]
async fn endpoint_open_names_a_refused_device() {
    let device = Device::new();
    let issuer = Issuer::start_as(&[], Rex::WebSocket).await;
    device.join(&issuer);

    let error = within("the refusal", async {
        let Err(error) = rex_endpoint(&device.service, issuer.endpoint.id())
            .open("/", CONTROL)
            .await
        else {
            panic!("a refused device cannot open the control socket");
        };
        error
    })
    .await;

    assert!(
        format!("{error:#}").contains("turned this device away"),
        "unclear refusal: {error:#}"
    );
}

#[tokio::test]
async fn endpoint_open_names_an_unjoined_id() {
    let device = Device::new();
    let stranger = SecretKey::generate().public();

    let error = rex_endpoint(&device.service, stranger)
        .open("/", CONTROL)
        .await
        .err()
        .expect("an unjoined id fails");

    assert!(
        format!("{error:#}").contains("no joined issuer has endpoint id"),
        "unclear error: {error:#}"
    );
}
