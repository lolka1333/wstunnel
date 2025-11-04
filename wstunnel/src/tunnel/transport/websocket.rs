use super::io::{MAX_PACKET_LENGTH, TunnelRead, TunnelWrite};
use super::packet_shaping::{calculate_realistic_buffer_growth};
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::WsClient;
use crate::tunnel::client::l4_transport_stream::{TransportReadHalf, TransportStream, TransportWriteHalf};
use crate::tunnel::transport::headers_from_file;
use crate::tunnel::transport::jwt::{JWT_HEADER_PREFIX, tunnel_to_jwt_token};
use crate::tunnel::transport::TransportScheme;
use anyhow::{Context, anyhow};
use bytes::{Bytes, BytesMut};
use fastwebsockets::{CloseCode, Frame, OpCode, Payload, Role, WebSocket, WebSocketRead, WebSocketWrite};
use http_body_util::Empty;
use hyper::Request;
use hyper::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE};
use hyper::header::{CONNECTION, HOST, SEC_WEBSOCKET_KEY};
use hyper::http::response::Parts;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use log::debug;
use std::io;
use std::io::ErrorKind;
use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_rustls::server::TlsStream;
use tracing::trace;
use uuid::Uuid;

pub struct WebsocketTunnelWrite {
    inner: WebSocketWrite<TransportWriteHalf>,
    buf: BytesMut,
    pending_operations: Receiver<Frame<'static>>,
    pending_ops_notify: Arc<Notify>,
    in_flight_ping: AtomicUsize,
}

impl WebsocketTunnelWrite {
    pub fn new(
        ws: WebSocketWrite<TransportWriteHalf>,
        (pending_operations, notify): (Receiver<Frame<'static>>, Arc<Notify>),
    ) -> Self {
        // Buffer capacity must be at least MAX_PACKET_LENGTH to satisfy debug_assert! in io.rs:124
        // which checks that chunk_mut().len() >= MAX_PACKET_LENGTH
        // We start with MAX_PACKET_LENGTH to satisfy the assertion, but the buffer growth
        // pattern (in the write() method) is optimized for realistic TCP packet sizes to avoid
        // DPI detection based on statistical anomalies.
        let buf = BytesMut::with_capacity(MAX_PACKET_LENGTH);
        
        Self {
            inner: ws,
            buf,
            pending_operations,
            pending_ops_notify: notify,
            in_flight_ping: AtomicUsize::new(0),
        }
    }
}

impl TunnelWrite for WebsocketTunnelWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        let buf = &mut self.buf;

        // For better DPI evasion, ensure WebSocket frames use realistic sizes
        // We DON'T modify the tunneled data (SSH/etc needs exact bytes!)
        // Instead, we just use the data as-is - the natural variation in read sizes
        // from TCP will create realistic browser-like patterns
        
        // Note: Adding padding to tunneled data breaks binary protocols like SSH!
        // Realistic packet sizes come from:
        // 1. Natural TCP read patterns (varies with network conditions)
        // 2. Buffer growth patterns (already mimics browser behavior)
        // 3. Variable WebSocket frame sizes (browser-typical from actual data)
        
        let actual_len = buf.len();
        let ret = self
            .inner
            .write_frame(Frame::binary(Payload::BorrowedMut(&mut buf[..actual_len])))
            .await;

        if let Err(err) = ret {
            return Err(io::Error::new(ErrorKind::ConnectionAborted, err));
        }

        // It is needed to call poll_flush to ensure that the data is written to the underlying stream.
        // In case of a TLS stream, it may still be buffered in the TLS layer if not flushed.
        // https://docs.rs/tokio-rustls/latest/tokio_rustls/#why-do-i-need-to-call-poll_flush
        if let Err(err) = self.inner.flush().await {
            return Err(io::Error::new(ErrorKind::ConnectionAborted, err));
        }

        // If the buffer has been completely filled with previous read, grow it!
        // For the buffer to not be a bottleneck when the TCP window scale.
        // We clamp it to 32MB to avoid unbounded growth and as websocket max frame size is 64MB by default
        // For udp, the buffer will never grow.
        // Growth pattern mimics browser behavior to avoid statistical anomalies
        const _32_MB: usize = 32 * 1024 * 1024;
        buf.clear();
        if buf.capacity() == actual_len && buf.capacity() < _32_MB {
            // Use realistic browser-like buffer growth pattern
            // This includes slight variations and alignment to typical browser buffer sizes
            let new_capacity = calculate_realistic_buffer_growth(buf.capacity(), actual_len);
            let growth_needed = new_capacity.saturating_sub(buf.capacity());
            
            if growth_needed > 0 && new_capacity <= _32_MB {
                buf.reserve(growth_needed);
                trace!(
                    "Buffer grown to {} MB (was {} MB, grew by {} KB) - mimics browser pattern",
                    buf.capacity() as f64 / 1024.0 / 1024.0,
                    (buf.capacity() - growth_needed) as f64 / 1024.0 / 1024.0,
                    growth_needed / 1024
                );
            }
        }

        Ok(())
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        if self.in_flight_ping.fetch_add(1, Relaxed) >= 3 {
            return Err(io::Error::new(
                ErrorKind::ConnectionAborted,
                "too many in flight/un-answered pings",
            ));
        }

        if let Err(err) = self
            .inner
            .write_frame(Frame::new(true, OpCode::Ping, None, Payload::BorrowedMut(&mut [])))
            .await
        {
            return Err(io::Error::new(ErrorKind::BrokenPipe, err));
        }

        Ok(())
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        if let Err(err) = self.inner.write_frame(Frame::close(1000, &[])).await {
            return Err(io::Error::new(ErrorKind::BrokenPipe, err));
        }

        Ok(())
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        self.pending_ops_notify.clone()
    }

    async fn handle_pending_operations(&mut self) -> Result<(), io::Error> {
        while let Ok(frame) = self.pending_operations.try_recv() {
            debug!("received frame {:?}", frame.opcode);
            match frame.opcode {
                OpCode::Close => {
                    if self.inner.write_frame(frame).await.is_err() {
                        return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send close frame"));
                    }
                }
                OpCode::Ping => {
                    debug!("sending pong frame");
                    if self.inner.write_frame(Frame::pong(frame.payload)).await.is_err() {
                        return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send pong frame"));
                    }
                }
                OpCode::Pong => {
                    debug!("received pong frame");
                    self.in_flight_ping.fetch_sub(1, Relaxed);
                }
                OpCode::Continuation | OpCode::Text | OpCode::Binary => unreachable!(),
            }
        }

        Ok(())
    }
}

pub struct WebsocketTunnelRead {
    inner: WebSocketRead<TransportReadHalf>,
    pending_operations: Sender<Frame<'static>>,
    notify_pending_ops: Arc<Notify>,
}

impl WebsocketTunnelRead {
    pub fn new(ws: WebSocketRead<TransportReadHalf>) -> (Self, (Receiver<Frame<'static>>, Arc<Notify>)) {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let notify = Arc::new(Notify::new());
        (
            Self {
                inner: ws,
                pending_operations: tx,
                notify_pending_ops: notify.clone(),
            },
            (rx, notify),
        )
    }
}

fn frame_reader(_: Frame<'_>) -> futures_util::future::Ready<anyhow::Result<()>> {
    //error!("frame {:?} {:?}", x.opcode, x.payload);
    futures_util::future::ready(anyhow::Ok(()))
}

impl TunnelRead for WebsocketTunnelRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        loop {
            let msg = match self.inner.read_frame(&mut frame_reader).await {
                Ok(msg) => msg,
                Err(err) => return Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
            };

            trace!("receive ws frame {:?} {:?}", msg.opcode, msg.payload);
            match msg.opcode {
                OpCode::Continuation | OpCode::Text | OpCode::Binary => {
                    return match writer.write_all(msg.payload.as_ref()).await {
                        Ok(_) => Ok(()),
                        Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
                    };
                }
                OpCode::Close => {
                    let _ = self
                        .pending_operations
                        .send(Frame::close(CloseCode::Normal.into(), &[]))
                        .await;
                    self.notify_pending_ops.notify_waiters();
                    return Err(io::Error::new(ErrorKind::NotConnected, "websocket close"));
                }
                OpCode::Ping => {
                    if self
                        .pending_operations
                        .send(Frame::new(true, msg.opcode, None, Payload::Owned(msg.payload.to_owned())))
                        .await
                        .is_err()
                    {
                        return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send ping"));
                    }
                    self.notify_pending_ops.notify_waiters();
                }
                OpCode::Pong => {
                    if self
                        .pending_operations
                        .send(Frame::pong(Payload::Borrowed(&[])))
                        .await
                        .is_err()
                    {
                        return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send pong"));
                    }
                    self.notify_pending_ops.notify_waiters();
                }
            };
        }
    }
}

pub async fn connect(
    request_id: Uuid,
    client: &WsClient<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(WebsocketTunnelRead, WebsocketTunnelWrite, Parts)> {
    let client_cfg = &client.config;
    let mut pooled_cnx = match client.cnx_pool.get().await {
        Ok(cnx) => Ok(cnx),
        Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}")),
    }?;

    // Automatically enable masking for unencrypted WebSocket connections (helps bypass DPI)
    // TLS connections don't need masking, but unencrypted WS connections benefit from it
    let should_mask = client_cfg.websocket_mask_frame || 
        matches!(client_cfg.remote_addr.scheme(), TransportScheme::Ws | TransportScheme::Http);
    
    let jwt_token = tunnel_to_jwt_token(request_id, dest_addr);
    
    // Build URI with realistic path structure (helps ML-based DPI see normal API patterns)
    // Real web apps often use paths like /api/v1/events or /ws/stream
    let uri_path = if client_cfg.http_upgrade_path_prefix == "v1" {
        format!("/api/v1/events") // More realistic API path
    } else {
        format!("/{}/events", &client_cfg.http_upgrade_path_prefix)
    };
    
    let mut req = Request::builder()
        .method("GET")
        .uri(&uri_path)
        .version(hyper::Version::HTTP_11);
    
    let headers = match req.headers_mut() {
        Some(h) => h,
        None => {
            return Err(anyhow!(
                "failed to build HTTP request to contact the server {:?}. Most likely path_prefix `{}` or http headers is not valid",
                req.body(Empty::<Bytes>::new()),
                client_cfg.http_upgrade_path_prefix
            ));
        }
    };
    
    // Build headers in Chrome's exact order for maximum ML-DPI evasion
    // Chrome sends headers in a specific order that ML models learn to recognize
    // Order: Host, Connection, Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version, Origin, Sec-WebSocket-Extensions, User-Agent, etc.
    let host_val = client_cfg.http_header_host.clone();
    let ws_key = fastwebsockets::handshake::generate_key();
    
    // Store JWT in Cookie for better obfuscation (looks like a normal session cookie)
    // This helps bypass DPI that looks for suspicious headers
    use hyper::header::{COOKIE, HeaderValue, USER_AGENT, ACCEPT_LANGUAGE, ACCEPT_ENCODING, CACHE_CONTROL, ORIGIN, SEC_WEBSOCKET_EXTENSIONS};
    
    // Chrome header order (critical for ML evasion):
    headers.insert(HOST, host_val);
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(SEC_WEBSOCKET_KEY, HeaderValue::from_str(&ws_key).unwrap());
    headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
    
    // Add Origin header (Chrome always sends it) - use the host header value
    if !headers.contains_key(ORIGIN) {
        let origin_val = client_cfg.http_header_host.to_str().ok()
            .map(|h| {
                let scheme = match client_cfg.remote_addr.scheme() {
                    TransportScheme::Wss | TransportScheme::Https => "https",
                    _ => "http",
                };
                format!("{}://{}", scheme, h)
            });
        if let Some(origin) = origin_val {
            if let Ok(origin_header) = HeaderValue::from_str(&origin) {
                let _ = headers.insert(ORIGIN, origin_header);
            }
        }
    }
    
    // Sec-WebSocket-Extensions header (Chrome sends this)
    if !headers.contains_key(SEC_WEBSOCKET_EXTENSIONS) {
        let _ = headers.insert(SEC_WEBSOCKET_EXTENSIONS, HeaderValue::from_static("permessage-deflate; client_max_window_bits"));
    }
    
    // Store JWT in Cookie (preferred) or fallback to Sec-WebSocket-Protocol
    if !headers.contains_key(COOKIE) {
        if let Ok(cookie_val) = HeaderValue::from_str(&format!("session={}", jwt_token)) {
            headers.insert(COOKIE, cookie_val);
        } else {
            // Fallback to Sec-WebSocket-Protocol if Cookie value is invalid
            headers.insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_str(&format!("chat, superchat, {}{}", JWT_HEADER_PREFIX, jwt_token)).unwrap());
        }
    } else {
        // If Cookie already exists, add JWT to Sec-WebSocket-Protocol with realistic subprotocols
        headers.insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_str(&format!("chat, superchat, {}{}", JWT_HEADER_PREFIX, jwt_token)).unwrap());
    }
    
    // Add realistic browser headers in Chrome's order (helps bypass ML-based DPI)
    if !headers.contains_key(USER_AGENT) {
        let _ = headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"));
    }
    
    // ✅ Chrome Client Hints (Sec-CH-*) - CRITICAL for ML-based DPI evasion
    // Chrome 90+ sends these headers by default. Their absence is a strong signal for ML models!
    // These headers are increasingly used by CDNs and DPI systems for fingerprinting
    use hyper::header::HeaderName;
    let sec_ch_ua = HeaderName::from_static("sec-ch-ua");
    let sec_ch_ua_mobile = HeaderName::from_static("sec-ch-ua-mobile");
    let sec_ch_ua_platform = HeaderName::from_static("sec-ch-ua-platform");
    
    if !headers.contains_key(&sec_ch_ua) {
        // Chrome 131 Client Hints format
        let _ = headers.insert(sec_ch_ua, HeaderValue::from_static("\"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\", \"Google Chrome\";v=\"131\""));
    }
    if !headers.contains_key(&sec_ch_ua_mobile) {
        let _ = headers.insert(sec_ch_ua_mobile, HeaderValue::from_static("?0"));
    }
    if !headers.contains_key(&sec_ch_ua_platform) {
        let _ = headers.insert(sec_ch_ua_platform, HeaderValue::from_static("\"Windows\""));
    }
    
    // ✅ Accept header - browsers always send this
    use hyper::header::ACCEPT;
    if !headers.contains_key(ACCEPT) {
        // WebSocket upgrade typically uses */* accept header
        let _ = headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    }
    
    if !headers.contains_key(ACCEPT_LANGUAGE) {
        let _ = headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    }
    if !headers.contains_key(ACCEPT_ENCODING) {
        let _ = headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, deflate, br"));
    }
    if !headers.contains_key(CACHE_CONTROL) {
        let _ = headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    }
    
    // ✅ Referer header - realistic navigation pattern
    // Browsers typically send Referer when upgrading WebSocket from a page
    // Pattern mimics user navigating from main site to establishing WebSocket
    use hyper::header::REFERER;
    if !headers.contains_key(REFERER) {
        // Generate realistic referer based on the target host
        if let Ok(host_str) = client_cfg.http_header_host.to_str() {
            let scheme = match client_cfg.remote_addr.scheme() {
                TransportScheme::Wss | TransportScheme::Https => "https",
                _ => "http",
            };
            // Realistic referer patterns: from main page or dashboard/app page
            // Use simple variation based on current time to avoid always same referer
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::from_secs(0));
            let variant = (now.as_secs() % 4) as usize;
            let referer_paths = ["", "/app", "/dashboard", "/api"];
            let referer = format!("{}://{}{}", scheme, host_str, referer_paths[variant]);
            if let Ok(referer_val) = HeaderValue::from_str(&referer) {
                let _ = headers.insert(REFERER, referer_val);
            }
        }
    }
    
    // Apply custom headers (user-defined headers override defaults)
    for (k, v) in &client_cfg.http_headers {
        let _ = headers.remove(k);
        headers.append(k, v.clone());
    }

    if let Some(auth) = &client_cfg.http_upgrade_credentials {
        let _ = headers.remove(AUTHORIZATION);
        headers.append(AUTHORIZATION, auth.clone());
    }

    if let Some(headers_file_path) = &client_cfg.http_headers_file {
        let (host, headers_file) = headers_from_file(headers_file_path);
        for (k, v) in headers_file {
            let _ = headers.remove(&k);
            headers.append(k, v);
        }
        if let Some((host, val)) = host {
            let _ = headers.remove(&host);
            headers.append(host, val);
        }
    }

    let req = req.body(Empty::<Bytes>::new()).with_context(|| {
        format!(
            "failed to build HTTP request to contact the server {:?}",
            client_cfg.remote_addr
        )
    })?;
    debug!("with HTTP upgrade request {req:?}");
    let transport = pooled_cnx.deref_mut().take().unwrap();
    let (ws, response) = fastwebsockets::handshake::client(&TokioExecutor::new(), req, transport)
        .await
        .with_context(|| format!("failed to do websocket handshake with the server {:?}", client_cfg.remote_addr))?;

    let (ws_rx, ws_tx) = mk_websocket_tunnel(ws, Role::Client, should_mask)?;
    Ok((ws_rx, ws_tx, response.into_parts().0))
}

pub fn mk_websocket_tunnel(
    ws: WebSocket<TokioIo<Upgraded>>,
    role: Role,
    mask_frame: bool,
) -> anyhow::Result<(WebsocketTunnelRead, WebsocketTunnelWrite)> {
    let mut ws = match role {
        Role::Client => {
            let stream = ws
                .into_inner()
                .into_inner()
                .downcast::<TokioIo<TransportStream>>()
                .map_err(|_| anyhow!("cannot downcast websocket client stream"))?;
            let transport = TransportStream::from(stream.io.into_inner(), stream.read_buf);
            WebSocket::after_handshake(transport, role)
        }
        Role::Server => {
            let upgraded = ws.into_inner().into_inner();
            match upgraded.downcast::<TokioIo<TlsStream<TcpStream>>>() {
                Ok(stream) => {
                    let transport = TransportStream::from_server_tls(stream.io.into_inner(), stream.read_buf);
                    WebSocket::after_handshake(transport, role)
                }
                Err(upgraded) => {
                    let stream = hyper_util::server::conn::auto::upgrade::downcast::<TokioIo<TcpStream>>(upgraded)
                        .map_err(|_| anyhow!("cannot downcast websocket server stream"))?;
                    let transport = TransportStream::from_tcp(stream.io.into_inner(), stream.read_buf);
                    WebSocket::after_handshake(transport, role)
                }
            }
        }
    };

    ws.set_auto_pong(false);
    ws.set_auto_close(false);
    ws.set_auto_apply_mask(mask_frame);
    let (ws_rx, ws_tx) = ws.split(|x| x.into_split());

    let (ws_rx, pending_ops) = WebsocketTunnelRead::new(ws_rx);
    Ok((ws_rx, WebsocketTunnelWrite::new(ws_tx, pending_ops)))
}
