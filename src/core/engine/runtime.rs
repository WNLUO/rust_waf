#[derive(Default)]
struct EntryListenerRuntimeState {
    http: Vec<RunningEntryListener>,
    https: Option<RunningEntryListener>,
}

struct RunningEntryListener {
    addr: String,
    shutdown_tx: mpsc::Sender<()>,
    task: JoinHandle<()>,
}

struct PrefixedStream<S> {
    prefix: Vec<u8>,
    cursor: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            cursor: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.cursor < self.prefix.len() {
            let remaining = self.prefix.len() - self.cursor;
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&self.prefix[self.cursor..self.cursor + to_copy]);
            self.cursor += to_copy;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct EntryListenerRuntime {
    state: Mutex<EntryListenerRuntimeState>,
}

fn is_benign_tls_disconnect(err: &anyhow::Error) -> bool {
    let message = err.to_string();
    message.contains("peer closed connection without sending TLS close_notify")
        || message.contains("unexpected eof")
}

impl EntryListenerRuntime {
    fn global() -> Arc<Self> {
        ENTRY_LISTENER_RUNTIME
            .get_or_init(|| {
                Arc::new(Self {
                    state: Mutex::new(EntryListenerRuntimeState::default()),
                })
            })
            .clone()
    }

    async fn validate_config(&self, context: Arc<WafContext>) -> Result<()> {
        let config = context.config_snapshot();
        let requested_http = config.listen_addrs.clone();
        let requested_https = config.gateway_config.https_listen_addr.trim().to_string();
        let tls_enabled = build_tls_acceptor(context.as_ref())?.is_some();

        let guard = self.state.lock().await;
        for addr in &requested_http {
            if guard.http.iter().any(|listener| listener.addr == *addr) {
                continue;
            }
            TcpListener::bind(addr).await.map_err(|err| {
                anyhow::anyhow!("HTTP 入口 {} 已被其他进程占用或无法监听: {}", addr, err)
            })?;
        }

        if !requested_https.is_empty() {
            if !tls_enabled {
                anyhow::bail!("当前没有可用证书，无法开启 HTTPS 入口端口");
            }
            let owned = guard
                .https
                .as_ref()
                .map(|listener| listener.addr == requested_https)
                .unwrap_or(false);
            if !owned {
                TcpListener::bind(&requested_https).await.map_err(|err| {
                    anyhow::anyhow!(
                        "HTTPS 入口 {} 已被其他进程占用或无法监听: {}",
                        requested_https,
                        err
                    )
                })?;
            }
        }

        Ok(())
    }

    async fn sync(
        &self,
        context: Arc<WafContext>,
        connection_semaphore: Arc<Semaphore>,
    ) -> Result<()> {
        let config = context.config_snapshot();
        let tls_acceptor = build_tls_acceptor(context.as_ref())?;
        let requested_http = config.listen_addrs.clone();
        let requested_https = config.gateway_config.https_listen_addr.trim().to_string();

        let mut guard = self.state.lock().await;
        let mut previous_http = std::mem::take(&mut guard.http);
        let previous_https = guard.https.take();
        drop(guard);

        let mut prepared_http = Vec::new();
        let mut stale_http = Vec::new();
        for listener in previous_http.drain(..) {
            if requested_http.iter().any(|addr| addr == &listener.addr) {
                prepared_http.push(listener);
            } else {
                stale_http.push(listener);
            }
        }
        for addr in &requested_http {
            if prepared_http.iter().any(|listener| &listener.addr == addr) {
                continue;
            }
            prepared_http.push(
                spawn_http_entry_listener(
                    addr,
                    Arc::clone(&context),
                    Arc::clone(&connection_semaphore),
                )
                .await?,
            );
        }

        let (prepared_https, stale_https) = if requested_https.is_empty() {
            (None, previous_https)
        } else if let Some(existing) = previous_https {
            if existing.addr == requested_https {
                (Some(existing), None)
            } else if let Some(acceptor) = tls_acceptor {
                (
                    Some(
                        spawn_https_entry_listener(
                            &requested_https,
                            acceptor,
                            Arc::clone(&context),
                            Arc::clone(&connection_semaphore),
                        )
                        .await?,
                    ),
                    Some(existing),
                )
            } else {
                (None, Some(existing))
            }
        } else if let Some(acceptor) = tls_acceptor {
            (
                Some(
                    spawn_https_entry_listener(
                        &requested_https,
                        acceptor,
                        Arc::clone(&context),
                        Arc::clone(&connection_semaphore),
                    )
                    .await?,
                ),
                None,
            )
        } else {
            (None, None)
        };

        let mut guard = self.state.lock().await;
        guard.http = prepared_http;
        guard.https = prepared_https;
        drop(guard);

        shutdown_entry_listeners(stale_http).await;
        if let Some(listener) = stale_https {
            shutdown_entry_listener(listener).await;
        }

        Ok(())
    }

    async fn shutdown_all(&self) {
        let mut guard = self.state.lock().await;
        let previous_http = std::mem::take(&mut guard.http);
        let previous_https = guard.https.take();
        drop(guard);

        shutdown_entry_listeners(previous_http).await;
        if let Some(listener) = previous_https {
            shutdown_entry_listener(listener).await;
        }
    }
}

pub struct WafEngine {
    context: Arc<WafContext>,
    _shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: mpsc::Receiver<()>,
    connection_semaphore: Arc<Semaphore>,
}

impl WafEngine {
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing WAF engine...");

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let concurrency_limit = config.max_concurrent_tasks.max(1);
        let context = Arc::new(WafContext::new(config).await?);

        Ok(Self {
            context,
            _shutdown_tx: shutdown_tx,
            shutdown_rx,
            connection_semaphore: Arc::new(Semaphore::new(concurrency_limit)),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        let startup_config = self.context.config_snapshot();
        info!("WAF engine started");
        info!(
            "Concurrency limit set to {} inflight connections",
            startup_config.max_concurrent_tasks
        );

        if let Some(l4_inspector) = self.context.l4_inspector() {
            l4_inspector.start(self.context.as_ref()).await?;
        }

        self.context
            .http_processor
            .start(self.context.as_ref())
            .await?;

        #[cfg(feature = "api")]
        if startup_config.api_enabled {
            let addr = startup_config.api_bind.parse()?;
            let context = Arc::clone(&self.context);
            tokio::spawn(async move {
                if let Err(err) = crate::api::ApiServer::new(addr, context).start().await {
                    warn!("API server exited with error: {}", err);
                }
            });
        }

        #[cfg(not(feature = "api"))]
        if startup_config.api_enabled {
            warn!("API support was requested but the binary was built without the 'api' feature");
        }

        let context = Arc::clone(&self.context);
        tokio::spawn(async move {
            super::engine_maintenance::run_upstream_healthcheck_loop(context).await;
        });

        if let Some(store) = self.context.sqlite_store.as_ref().cloned() {
            let fallback_config = startup_config.clone();
            tokio::spawn(async move {
                super::engine_maintenance::run_safeline_auto_sync_loop(store, fallback_config)
                    .await;
            });
        }

        let maintenance_interval = startup_config.maintenance_interval_secs.max(5);
        let mut maintenance =
            tokio::time::interval(tokio::time::Duration::from_secs(maintenance_interval));

        // 创建多个监听器，每个监听器在独立任务中运行
        let mut shutdown_senders = Vec::new();
        let mut udp_listener_addresses = Vec::new();
        #[cfg(feature = "http3")]
        let mut quic_listener = None;

        // 先绑定所有 UDP 监听器
        for addr in &startup_config.listen_addrs {
            match UdpSocket::bind(addr).await {
                Ok(socket) => {
                    let addr = socket.local_addr()?;
                    udp_listener_addresses.push((addr, Arc::new(socket)));
                }
                Err(err) => {
                    warn!("Failed to bind UDP listener on {}: {}", addr, err);
                }
            }
        }

        #[cfg(feature = "http3")]
        {
            if let Some(endpoint) =
                super::engine_tls::build_http3_endpoint(&startup_config.http3_config)?
            {
                let addr = endpoint.local_addr()?;
                self.context
                    .set_http3_runtime("running", true, Some(addr.to_string()), None);
                quic_listener = Some((addr, endpoint));
            } else {
                let config = &startup_config.http3_config;
                let (status, last_error) = if !config.enabled {
                    ("disabled".to_string(), None)
                } else if !config.enable_tls13 {
                    (
                        "degraded".to_string(),
                        Some("HTTP/3 requires TLS 1.3".to_string()),
                    )
                } else if config.certificate_path.is_none() || config.private_key_path.is_none() {
                    (
                        "degraded".to_string(),
                        Some("certificate_path/private_key_path are missing".to_string()),
                    )
                } else {
                    (
                        "pending".to_string(),
                        Some("HTTP/3 listener was not started".to_string()),
                    )
                };
                self.context
                    .set_http3_runtime(status, false, None, last_error);
            }
        }

        #[cfg(not(feature = "http3"))]
        if startup_config.http3_config.enabled {
            self.context.set_http3_runtime(
                "unsupported",
                false,
                None,
                Some("Binary was built without the 'http3' feature".to_string()),
            );
            warn!(
                "HTTP/3 support was requested but the binary was built without the 'http3' feature"
            );
        } else {
            self.context
                .set_http3_runtime("disabled", false, None, None);
        }

        #[cfg(feature = "http3")]
        let has_quic_listener = quic_listener.is_some();
        #[cfg(not(feature = "http3"))]
        let _has_quic_listener = false;

        // 为每个UDP监听器启动独立任务
        for (addr, socket) in udp_listener_addresses {
            info!("UDP inspection listener started on {}", addr);
            let context = Arc::clone(&self.context);
            let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
            let connection_semaphore = Arc::clone(&self.connection_semaphore);

            let task = tokio::spawn(async move {
                let mut buffer = vec![0u8; 65_535];
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            info!("UDP listener shutdown signal received for {}", addr);
                            break;
                        }
                        recv_result = socket.recv_from(&mut buffer) => {
                            match recv_result {
                                Ok((bytes_read, peer_addr)) => {
                                    match connection_semaphore.clone().try_acquire_owned() {
                                        Ok(permit) => {
                                            let ctx = Arc::clone(&context);
                                            let listener_socket = Arc::clone(&socket);
                                            let payload = buffer[..bytes_read].to_vec();
                                            tokio::spawn(async move {
                                                if let Err(err) = handle_udp_datagram(
                                                    ctx,
                                                    listener_socket,
                                                    peer_addr,
                                                    addr,
                                                    payload,
                                                    permit,
                                                ).await {
                                                    warn!("UDP datagram handling failed: {}", err);
                                                }
                                            });
                                        }
                                        Err(_) => {
                                            warn!(
                                                "Dropping UDP datagram from {} due to concurrency limit",
                                                peer_addr
                                            );
                                        }
                                    }
                                }
                                Err(err) => {
                                    warn!("Failed to receive UDP datagram on {}: {}", addr, err);
                                }
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            info!("Ctrl+C received, shutting down UDP listener on {}", addr);
                            break;
                        }
                    }
                }
            });
            shutdown_senders.push((task, shutdown_tx));
        }

        #[cfg(feature = "http3")]
        if let Some((addr, endpoint)) = quic_listener {
            info!("HTTP/3 listener started on {}", addr);
            let context = Arc::clone(&self.context);
            let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
            let connection_semaphore = Arc::clone(&self.connection_semaphore);

            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            info!("HTTP/3 listener shutdown signal received for {}", addr);
                            break;
                        }
                        accept_result = endpoint.accept() => {
                            match accept_result {
                                Some(incoming) => {
                                    match connection_semaphore.clone().try_acquire_owned() {
                                        Ok(permit) => {
                                            let ctx = Arc::clone(&context);
                                            tokio::spawn(async move {
                                                if let Err(err) =
                                                    handle_http3_quic_connection(ctx, incoming, addr, permit).await
                                                {
                                                    warn!("HTTP/3 connection handling failed: {}", err);
                                                }
                                            });
                                        }
                                        Err(_) => {
                                            warn!(
                                                "Dropping HTTP/3 connection on {} due to concurrency limit",
                                                addr
                                            );
                                        }
                                    }
                                }
                                None => break,
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            info!("Ctrl+C received, shutting down HTTP/3 listener on {}", addr);
                            break;
                        }
                    }
                }
            });
            shutdown_senders.push((task, shutdown_tx));
        }

        info!(
            "Successfully started {} listener task(s)",
            shutdown_senders.len()
        );

        let entry_runtime = EntryListenerRuntime::global();
        entry_runtime
            .sync(
                Arc::clone(&self.context),
                Arc::clone(&self.connection_semaphore),
            )
            .await?;

        // 主循环处理维护任务
        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    // 通知所有监听器任务关闭
                    for (_, shutdown_tx) in &shutdown_senders {
                        let _ = shutdown_tx.send(()).await;
                    }
                    entry_runtime.shutdown_all().await;
                    break Ok(());
                }
                _ = maintenance.tick() => {
                    self.run_maintenance().await;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C received, shutting down");
                    // 通知所有监听器任务关闭
                    for (_, shutdown_tx) in &shutdown_senders {
                        let _ = shutdown_tx.send(()).await;
                    }
                    entry_runtime.shutdown_all().await;
                    break Ok(());
                }
            }
        }
    }

    async fn run_maintenance(&self) {
        if let Err(err) = self.context.refresh_rules_from_storage().await {
            warn!("Failed to refresh rules from SQLite: {}", err);
        }

        if let Some(l4_inspector) = self.context.l4_inspector() {
            l4_inspector.maintenance_tick();
            if matches!(
                self.context.config_snapshot().runtime_profile,
                RuntimeProfile::Standard
            ) {
                let stats = l4_inspector.get_statistics();
                debug!(
                    "Maintenance tick: active_connections={}, blocked_connections={}, rate_limit_hits={}",
                    stats.connections.active_connections,
                    stats.connections.blocked_connections,
                    stats.connections.rate_limit_hits
                );
                debug!(
                    "L4 counters: ddos_events={}, protocol_anomalies={}, traffic={}, defense_actions={}",
                    stats.ddos_events,
                    stats.protocol_anomalies,
                    stats.traffic,
                    stats.defense_actions
                );

                // Display per-port statistics
                if !stats.per_port_stats.is_empty() {
                    debug!("=== Per-Port Statistics ===");
                    for (port, port_stats) in &stats.per_port_stats {
                        debug!(
                            "Port {}: connections={}, blocks={}, ddos_events={}",
                            port, port_stats.connections, port_stats.blocks, port_stats.ddos_events
                        );
                    }
                    debug!("=============================");
                }
            }
        }
    }
}

pub async fn validate_entry_listener_config(context: Arc<WafContext>) -> Result<()> {
    EntryListenerRuntime::global()
        .validate_config(context)
        .await
}

pub async fn sync_entry_listener_runtime(
    context: Arc<WafContext>,
    concurrency_limit: usize,
) -> Result<()> {
    EntryListenerRuntime::global()
        .sync(context, Arc::new(Semaphore::new(concurrency_limit.max(1))))
        .await
}

async fn spawn_http_entry_listener(
    addr: &str,
    context: Arc<WafContext>,
    connection_semaphore: Arc<Semaphore>,
) -> Result<RunningEntryListener> {
    let listener = TcpListener::bind(addr).await?;
    let addr_string = listener.local_addr()?.to_string();
    info!("HTTP inspection listener started on {}", addr_string);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let task_addr = addr_string.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("HTTP listener shutdown signal received for {}", task_addr);
                    break;
                }
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            match connection_semaphore.clone().try_acquire_owned() {
                                Ok(permit) => {
                                    let ctx = Arc::clone(&context);
                                    tokio::spawn(async move {
                                        if let Err(err) = handle_connection(ctx, stream, peer_addr, permit).await {
                                            warn!("Connection handling failed: {}", err);
                                        }
                                    });
                                }
                                Err(_) => {
                                    warn!(
                                        "Dropping connection from {} due to concurrency limit",
                                        peer_addr
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            warn!("Failed to accept connection on {}: {}", task_addr, err);
                        }
                    }
                }
            }
        }
    });

    Ok(RunningEntryListener {
        addr: addr_string,
        shutdown_tx,
        task,
    })
}

async fn spawn_https_entry_listener(
    addr: &str,
    tls_acceptor: TlsAcceptor,
    context: Arc<WafContext>,
    connection_semaphore: Arc<Semaphore>,
) -> Result<RunningEntryListener> {
    let listener = TcpListener::bind(addr).await?;
    let addr_string = listener.local_addr()?.to_string();
    info!("TLS inspection listener started on {}", addr_string);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let task_addr = addr_string.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("TLS listener shutdown signal received for {}", task_addr);
                    break;
                }
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            match connection_semaphore.clone().try_acquire_owned() {
                                Ok(permit) => {
                                    let ctx = Arc::clone(&context);
                                    let acceptor = tls_acceptor.clone();
                                    tokio::spawn(async move {
                                        if let Err(err) = handle_tls_connection(ctx, acceptor, stream, peer_addr, permit).await {
                                            if is_benign_tls_disconnect(&err) {
                                                debug!(
                                                    "TLS connection closed without close_notify from {}: {}",
                                                    peer_addr, err
                                                );
                                            } else {
                                                warn!("TLS connection handling failed: {}", err);
                                            }
                                        }
                                    });
                                }
                                Err(_) => {
                                    warn!(
                                        "Dropping TLS connection from {} due to concurrency limit",
                                        peer_addr
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            warn!("Failed to accept TLS connection on {}: {}", task_addr, err);
                        }
                    }
                }
            }
        }
    });

    Ok(RunningEntryListener {
        addr: addr_string,
        shutdown_tx,
        task,
    })
}

async fn shutdown_entry_listeners(listeners: Vec<RunningEntryListener>) {
    for listener in listeners {
        shutdown_entry_listener(listener).await;
    }
}

async fn shutdown_entry_listener(listener: RunningEntryListener) {
    let _ = listener.shutdown_tx.send(()).await;
    let _ = listener.task.await;
}

#[cfg_attr(not(test), allow(dead_code))]
fn build_tls_acceptor(context: &WafContext) -> Result<Option<tokio_rustls::TlsAcceptor>> {
    super::engine_tls::build_tls_acceptor(context)
}

#[cfg_attr(not(test), allow(dead_code))]
#[cfg(feature = "http3")]
fn build_http3_endpoint(config: &crate::config::Http3Config) -> Result<Option<quinn::Endpoint>> {
    super::engine_tls::build_http3_endpoint(config)
}
