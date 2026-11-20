use anyhow::{Context, Result, bail, ensure};
use futures_util::{Sink, Stream};
use percent_encoding::percent_decode_str;
#[cfg(feature = "iroh")]
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::{
    client_async_with_config, connect_async_with_config,
    tungstenite::{self, Message, client::IntoClientRequest, protocol::WebSocketConfig},
};
use url::Url;

pub const CONTROL: &str = "rex.control.v1";
pub const TERMINAL: &str = "rex.data.terminal.v1";
pub const MAX_MESSAGE: usize = 1_048_576;

pub trait Socket:
    Stream<Item = Result<Message, tungstenite::Error>>
    + Sink<Message, Error = tungstenite::Error>
    + Unpin
    + Send
{
}
impl<T> Socket for T where
    T: Stream<Item = Result<Message, tungstenite::Error>>
        + Sink<Message, Error = tungstenite::Error>
        + Unpin
        + Send
{
}
pub type Ws = Box<dyn Socket>;

/// The scheme of a Rex server reached through rex-iroh. Its host is the
/// issuer's endpoint id as 64 lowercase hex digits.
pub const IROH_SCHEME: &str = "rex-iroh";

#[derive(Clone)]
pub struct Endpoint {
    url: Url,
    pub timeout: Duration,

    /// The iroh service `rex-iroh` endpoints dial through.
    #[cfg(feature = "iroh")]
    iroh: Option<Arc<crate::iroh::Service>>,
}

fn is_endpoint_id(host: &str) -> bool {
    host.len() == 64 && host.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Endpoint {
    pub fn new(server: &str, timeout: Duration) -> Result<Self> {
        let url = Url::parse(server).context("use an explicit unix://, https://, http://, wss://, or ws:// URL (host labels are CLI-only)")?;
        ensure!(
            matches!(url.scheme(), "unix" | "https" | "http" | "wss" | "ws" | "ssh" | IROH_SCHEME),
            "unsupported server scheme"
        );
        #[cfg(not(feature = "iroh"))]
        ensure!(
            url.scheme() != IROH_SCHEME,
            "rex-iroh endpoints need a build with the iroh feature"
        );
        ensure!(
            (url.username().is_empty() || url.scheme() == "ssh") && url.password().is_none(),
            "login-server account selection is not implemented; URL credentials are not accepted"
        );
        ensure!(
            url.query().is_none() && url.fragment().is_none(),
            "server URL must not contain a query or fragment"
        );
        if url.scheme() == "unix" {
            ensure!(
                url.host_str().is_none() && !url.path().is_empty(),
                "use unix:///absolute/socket/path"
            );
        } else if url.scheme() == "ssh" {
            ensure!(url.host_str().is_some() && !url.username().is_empty(), "SSH requires a host and username");
        } else if url.scheme() == IROH_SCHEME {
            ensure!(
                url.port().is_none() && matches!(url.path(), "" | "/"),
                "rex-iroh URL must be rex-iroh://<64 lowercase hex digits> with no port or path"
            );
            ensure!(
                url.host_str().is_some_and(is_endpoint_id),
                "rex-iroh host must be the issuer's endpoint id: 64 lowercase hex digits"
            );
        } else {
            ensure!(
                url.host_str().is_some() && matches!(url.path(), "" | "/"),
                "network URL must name a server root"
            );
        }
        ensure!(!timeout.is_zero(), "timeout must be positive");
        Ok(Self {
            url,
            timeout,
            #[cfg(feature = "iroh")]
            iroh: None,
        })
    }

    /// Attach the iroh service that `rex-iroh` endpoints dial through.
    #[cfg(feature = "iroh")]
    pub fn with_iroh(mut self, service: Arc<crate::iroh::Service>) -> Self {
        self.iroh = Some(service);
        self
    }

    pub async fn open(&self, path: &str, protocol: &str) -> Result<Ws> {
        let unix = self.url.scheme() == "unix";
        let ssh = self.url.scheme() == "ssh";
        let iroh = self.url.scheme() == IROH_SCHEME;
        let mut url = if unix || ssh || iroh {
            Url::parse("ws://localhost")?
        } else {
            self.url.clone()
        };
        if !unix && !ssh && !iroh {
            let scheme = match url.scheme() {
                "https" => "wss",
                "http" => "ws",
                s => s,
            };
            let scheme = scheme.to_owned();
            url.set_scheme(&scheme)
                .map_err(|_| anyhow::anyhow!("invalid WebSocket scheme"))?;
        }
        url.set_path(path);
        let mut request = url.as_str().into_client_request()?;
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", protocol.parse()?);
        // No identity headers, compression, cookies, redirects, or TLS bypasses.
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE))
            .max_frame_size(Some(MAX_MESSAGE));
        let operation = async {
            let (socket, response): (Ws, _) = if unix {
                #[cfg(unix)]
                {
                    let path = percent_decode_str(self.url.path())
                        .decode_utf8()
                        .context("socket path isn't UTF-8")?;
                    let stream = tokio::net::UnixStream::connect(path.as_ref())
                        .await
                        .context("connect Unix socket")?;
                    let (ws, response) =
                        client_async_with_config(request, stream, Some(config)).await?;
                    (Box::new(ws), response)
                }
                #[cfg(not(unix))]
                {
                    bail!("Unix sockets are unsupported on this platform");
                }
            } else if iroh {
                #[cfg(feature = "iroh")]
                {
                    let service = self
                        .iroh
                        .clone()
                        .context("no iroh service is attached to this rex-iroh endpoint")?;
                    let id = crate::iroh::parse_endpoint_id(self.url.host_str().unwrap_or_default())?;
                    // No TLS here: the iroh connection already encrypts and authenticates.
                    let stream = service.connect(id).await?;
                    match client_async_with_config(request, stream, Some(config)).await {
                        Ok((ws, response)) => (Box::new(ws), response),
                        Err(error) => {
                            if let Some(message) = service.refusal_for(id).await {
                                bail!(message);
                            }
                            return Err(error.into());
                        }
                    }
                }
                #[cfg(not(feature = "iroh"))]
                {
                    bail!("rex-iroh endpoints need a build with the iroh feature");
                }
            } else {
                #[cfg(target_os = "android")]
                if ssh || crate::network::enabled() {
                    let stream = crate::network::connect(self.url.to_string(), self.timeout).await?;
                    let (ws, response) = tokio_tungstenite::client_async_tls_with_config(request, stream, Some(config), None).await?;
                    ensure!(response.headers().get("Sec-WebSocket-Protocol").and_then(|h|h.to_str().ok()) == Some(protocol), "server did not negotiate {protocol}");
                    return Ok(Box::new(ws) as Ws);
                }
                ensure!(!ssh, "SSH transport is available in the Android app");
                let (ws, response) = connect_async_with_config(request, Some(config), true)
                    .await
                    .context(
                        "direct WebSocket connection (check Tailscale and the existing listener)",
                    )?;
                (Box::new(ws), response)
            };
            ensure!(
                response
                    .headers()
                    .get("Sec-WebSocket-Protocol")
                    .and_then(|h| h.to_str().ok())
                    == Some(protocol),
                "server did not negotiate {protocol}"
            );
            Ok(socket)
        };
        tokio::time::timeout(self.timeout, operation)
            .await
            .context("connection timeout")?
    }
}

/// Read application frames while servicing automatic WebSocket pong/close replies.
pub async fn receive(ws: &mut Ws) -> Result<Message> {
    use futures_util::{SinkExt, StreamExt};
    loop {
        let frame = ws.next().await.context("WebSocket ended")??;
        match frame {
            Message::Ping(_) | Message::Pong(_) => ws.flush().await?,
            Message::Close(close) => {
                let _ = ws.flush().await;
                bail!("WebSocket closed: {close:?}");
            }
            Message::Frame(_) => continue,
            frame => return Ok(frame),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_endpoints_only() {
        for url in [
            "unix:///tmp/a%20b.sock",
            "https://rex.example.ts.net",
            "http://100.100.1.2:7297",
        ] {
            assert!(Endpoint::new(url, Duration::from_secs(3)).is_ok());
        }
        for url in [
            "host-label",
            "https://user@rex",
            "https://rex/path",
            "https://rex/?token=secret",
            "ftp://rex",
        ] {
            assert!(Endpoint::new(url, Duration::from_secs(3)).is_err());
        }
    }

    #[test]
    fn rex_iroh_needs_a_lowercase_endpoint_id_host() {
        let id = "ab".repeat(32);
        let accepted = Endpoint::new(&format!("{IROH_SCHEME}://{id}"), Duration::from_secs(3));
        let uppercase = Endpoint::new(
            &format!("{IROH_SCHEME}://{}", id.to_uppercase()),
            Duration::from_secs(3),
        );
        let short = Endpoint::new(&format!("{IROH_SCHEME}://abcd"), Duration::from_secs(3));
        let with_port = Endpoint::new(&format!("{IROH_SCHEME}://{id}:9"), Duration::from_secs(3));

        assert_eq!(accepted.is_ok(), cfg!(feature = "iroh"));
        assert!(uppercase.is_err());
        assert!(short.is_err());
        assert!(with_port.is_err());
    }

    #[cfg(not(feature = "iroh"))]
    #[test]
    fn rex_iroh_is_refused_without_the_iroh_feature() {
        let error = Endpoint::new(
            &format!("{IROH_SCHEME}://{}", "ab".repeat(32)),
            Duration::from_secs(3),
        )
        .err()
        .expect("rex-iroh is refused");
        assert!(error.to_string().contains("iroh feature"), "{error}");
    }
}
