use super::cookies::generate_realistic_cookies;
use super::io::{MAX_PACKET_LENGTH, TunnelRead, TunnelWrite};
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::WsClient;
use crate::tunnel::transport::jwt::tunnel_to_jwt_token;
use crate::tunnel::transport::{TransportScheme, headers_from_file};
use anyhow::{Context, anyhow};
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, BodyStream, StreamBody};
use hyper::Request;
use hyper::body::{Frame, Incoming};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, USER_AGENT, ACCEPT_LANGUAGE, ACCEPT_ENCODING};
use hyper::http::response::Parts;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use log::{debug, error, warn};
use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tokio::task::AbortHandle;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

pub struct Http2TunnelRead {
    inner: BodyStream<Incoming>,
    cnx_poller: Option<AbortHandle>,
}

impl Http2TunnelRead {
    pub const fn new(inner: BodyStream<Incoming>, cnx_poller: Option<AbortHandle>) -> Self {
        Self { inner, cnx_poller }
    }
}

impl Drop for Http2TunnelRead {
    fn drop(&mut self) {
        if let Some(t) = self.cnx_poller.as_ref() {
            t.abort()
        }
    }
}

impl TunnelRead for Http2TunnelRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        loop {
            match self.inner.next().await {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        return match writer.write_all(data.as_ref()).await {
                            Ok(_) => Ok(()),
                            Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
                        };
                    }
                    Err(err) => {
                        warn!("{err:?}");
                        continue;
                    }
                },
                Some(Err(err)) => {
                    return Err(io::Error::new(ErrorKind::ConnectionAborted, err));
                }
                None => return Err(io::Error::new(ErrorKind::BrokenPipe, "closed")),
            }
        }
    }
}

pub struct Http2TunnelWrite {
    inner: mpsc::Sender<Bytes>,
    buf: BytesMut,
}

impl Http2TunnelWrite {
    pub fn new(inner: mpsc::Sender<Bytes>) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(MAX_PACKET_LENGTH * 20), // ~ 1Mb
        }
    }
}

impl TunnelWrite for Http2TunnelWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        let data = self.buf.split().freeze();
        let ret = match self.inner.send(data).await {
            Ok(_) => Ok(()),
            Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
        };

        if self.buf.capacity() < MAX_PACKET_LENGTH {
            //info!("read {} Kb {} Kb", self.buf.capacity() / 1024, old_capa / 1024);
            self.buf.reserve(MAX_PACKET_LENGTH)
        }

        ret
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        Ok(())
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        Ok(())
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        Arc::new(Notify::new())
    }

    fn handle_pending_operations(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        std::future::ready(Ok(()))
    }
}

pub async fn connect(
    request_id: Uuid,
    client: &WsClient<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(Http2TunnelRead, Http2TunnelWrite, Parts)> {
    let mut pooled_cnx = match client.cnx_pool.get().await {
        Ok(cnx) => Ok(cnx),
        Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}")),
    }?;

    // In http2 HOST header does not exist, it is explicitly set in the authority from the request uri
    let (headers_file, authority) =
        client
            .config
            .http_headers_file
            .as_ref()
            .map_or((None, None), |headers_file_path| {
                let (host, headers) = headers_from_file(headers_file_path);
                let host = if let Some((_, v)) = host {
                    match (client.config.remote_addr.scheme(), client.config.remote_addr.port()) {
                        (TransportScheme::Http, 80) | (TransportScheme::Https, 443) => {
                            Some(v.to_str().unwrap_or("").to_string())
                        }
                        (_, port) => Some(format!("{}:{}", v.to_str().unwrap_or(""), port)),
                    }
                } else {
                    None
                };

                (Some(headers), host)
            });

    let jwt_token = tunnel_to_jwt_token(request_id, dest_addr);
    
    // ⚠️ HTTP/2 Stream Priority (PRIORITY frame):
    //
    // Chrome uses a complex priority tree for HTTP/2 streams:
    // - Stream 0 (connection): root of priority tree
    // - CSS/JS: high weight (256)
    // - Images: medium weight (128)
    // - Async requests: low weight (64)
    //
    // LIMITATION: hyper/h2 doesn't expose API for setting stream priority/weight
    // To implement Chrome-exact priority would require:
    // 1. Using h2 crate directly (instead of hyper)
    // 2. Manually constructing PRIORITY frames
    // 3. Managing stream dependency tree
    //
    // For wstunnel use case (single long-lived POST stream), priority tree is less critical
    // since we only have ONE stream, not multiple parallel streams like a browser
    //
    // If needed in future, could use h2::client::SendRequest::send_request_with_priority()
    // But this requires rewriting the entire HTTP/2 layer to use h2 directly
    
    let mut req = Request::builder()
        .method("POST")
        .uri(format!(
            "{}://{}/{}/events",
            client.config.remote_addr.scheme(),
            authority
                .as_deref()
                .unwrap_or_else(|| client.config.http_header_host.to_str().unwrap_or("")),
            &client.config.http_upgrade_path_prefix
        ))
        // ✅ Cookie Evolution: Use realistic cookies instead of just session token
        // Browsers accumulate analytics and tracking cookies that DPI systems expect to see
        .header(COOKIE, generate_realistic_cookies(&jwt_token))
        .header(CONTENT_TYPE, "application/json")
        .version(hyper::Version::HTTP_2);

    let headers = match req.headers_mut() {
        Some(h) => h,
        None => {
            return Err(anyhow!(
                "failed to build HTTP request to contact the server {:?}. Most likely path_prefix `{}` or http headers is not valid",
                req,
                client.config.http_upgrade_path_prefix
            ));
        }
    };
    // Add realistic browser headers if not already set (helps bypass DPI)
    if !headers.contains_key(USER_AGENT) {
        let _ = headers.insert(USER_AGENT, hyper::header::HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"));
    }
    if !headers.contains_key(ACCEPT_LANGUAGE) {
        let _ = headers.insert(ACCEPT_LANGUAGE, hyper::header::HeaderValue::from_static("en-US,en;q=0.9"));
    }
    if !headers.contains_key(ACCEPT_ENCODING) {
        let _ = headers.insert(ACCEPT_ENCODING, hyper::header::HeaderValue::from_static("gzip, deflate, br"));
    }
    
    // Apply custom headers (user-defined headers override defaults)
    for (k, v) in &client.config.http_headers {
        let _ = headers.remove(k);
        headers.append(k, v.clone());
    }

    if let Some(auth) = &client.config.http_upgrade_credentials {
        let _ = headers.remove(AUTHORIZATION);
        headers.append(AUTHORIZATION, auth.clone());
    }

    if let Some(headers_file) = headers_file {
        for (k, v) in headers_file {
            let _ = headers.remove(&k);
            headers.append(k, v);
        }
    }

    let (tx, rx) = mpsc::channel::<Bytes>(1024);
    let body = StreamBody::new(ReceiverStream::new(rx).map(|s| -> anyhow::Result<Frame<Bytes>> { Ok(Frame::data(s)) }));
    let req = req.body(body).with_context(|| {
        format!(
            "failed to build HTTP request to contact the server {:?}",
            client.config.remote_addr
        )
    })?;
    debug!("with HTTP upgrade request {req:?}");
    
    // ✅ Connection Timing: Realistic delay before HTTP/2 connection (like WebSocket)
    // Browsers have natural processing delays between TLS handshake and HTTP/2 setup
    {
        use std::time::Duration;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0));
        let jitter_ms = 3 + ((now.as_nanos() % 6) as u64); // 3-8ms
        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
    }
    
    let transport = pooled_cnx.deref_mut().take().unwrap();
    
    // ✅ Configure HTTP/2 with Chrome 120+ SETTINGS frame values
    // Chrome sends specific HTTP/2 SETTINGS during connection preface
    // These values are fingerprinted by advanced DPI systems
    //
    // Chrome 120+ SETTINGS frame:
    // HEADER_TABLE_SIZE (1): 65536 (default, but explicitly set in Chrome)
    // ENABLE_PUSH (2): 0 (Chrome disables server push)
    // MAX_CONCURRENT_STREAMS (3): 1000 (Chrome default for client)
    // INITIAL_WINDOW_SIZE (4): 6291456 (6MB - Chrome default)
    // MAX_FRAME_SIZE (5): 16384 (16KB - Chrome default)
    // MAX_HEADER_LIST_SIZE (6): 262144 (256KB - Chrome default)
    //
    let (mut request_sender, cnx) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        // ✅ Chrome HTTP/2 SETTINGS (exact values from Chrome 120+)
        .adaptive_window(true)                                    // Chrome uses adaptive window
        .initial_connection_window_size(Some(10 * 1024 * 1024)) // 10MB connection window
        .initial_stream_window_size(Some(6 * 1024 * 1024))      // 6MB stream window (Chrome INITIAL_WINDOW_SIZE)
        .max_frame_size(Some(16384))                             // 16KB max frame (Chrome MAX_FRAME_SIZE)
        .max_concurrent_streams(Some(1000))                      // Chrome MAX_CONCURRENT_STREAMS
        .max_header_list_size(256 * 1024)                        // 256KB (Chrome MAX_HEADER_LIST_SIZE)
        // Keep-alive settings
        .keep_alive_interval(client.config.websocket_ping_frequency)
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(false)                            // Chrome doesn't ping idle connections
        // Note: HEADER_TABLE_SIZE and ENABLE_PUSH are managed by hyper internally
        // hyper sets HEADER_TABLE_SIZE=4096 by default (we use default)
        // hyper sets ENABLE_PUSH=0 automatically for clients (matches Chrome)
        .handshake(TokioIo::new(transport))
        .await
        .with_context(|| format!("failed to do http2 handshake with the server {:?}", client.config.remote_addr))?;
    let cnx_poller = client.executor.spawn(async move {
        if let Err(err) = cnx.await {
            error!("{err:?}")
        }
    });

    let response = request_sender
        .send_request(req)
        .await
        .with_context(|| format!("failed to send http2 request with the server {:?}", client.config.remote_addr))?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Http2 server rejected the connection: {:?}: {:?}",
            response.status(),
            String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec()).unwrap_or_default()
        ));
    }

    // ✅ Connection Timing: Realistic delay after receiving HTTP/2 response
    // Chrome processes response headers before starting data transfer
    // Typical delay: 2-5ms (response parsing, stream initialization)
    {
        use std::time::Duration;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0));
        let jitter_ms = 2 + ((now.as_nanos() % 4) as u64); // 2-5ms
        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
    }

    let (parts, body) = response.into_parts();
    Ok((
        Http2TunnelRead::new(BodyStream::new(body), Some(cnx_poller)),
        Http2TunnelWrite::new(tx),
        parts,
    ))
}
