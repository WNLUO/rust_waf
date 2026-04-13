use super::*;
use crate::core::engine_tls;

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

#[cfg(feature = "http3")]
struct RunningHttp3Listener {
    addr: String,
    config_key: String,
    shutdown_tx: mpsc::Sender<()>,
    task: JoinHandle<()>,
}

#[cfg(feature = "http3")]
#[derive(Default)]
struct Http3ListenerRuntimeState {
    listener: Option<RunningHttp3Listener>,
}

pub(super) struct EntryListenerRuntime {
    state: Mutex<EntryListenerRuntimeState>,
}

#[cfg(feature = "http3")]
pub(super) struct Http3ListenerRuntime {
    state: Mutex<Http3ListenerRuntimeState>,
}

fn is_benign_tls_disconnect(err: &anyhow::Error) -> bool {
    let message = err.to_string();
    message.contains("peer closed connection without sending TLS close_notify")
        || message.contains("unexpected eof")
}

impl EntryListenerRuntime {
    pub(super) fn global() -> Arc<Self> {
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
        let owned_http = guard
            .http
            .iter()
            .map(|listener| listener.addr.clone())
            .collect::<Vec<_>>();
        let owned_https = guard.https.as_ref().map(|listener| listener.addr.clone());
        drop(guard);

        for addr in &requested_http {
            if owned_http.iter().any(|listener| listener == addr) {
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
            let owned = owned_https
                .as_ref()
                .map(|listener| listener == &requested_https)
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

    pub(super) async fn sync(
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

    pub(super) async fn shutdown_all(&self) {
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

#[cfg(feature = "http3")]
impl Http3ListenerRuntime {
    pub(super) fn global() -> Arc<Self> {
        HTTP3_LISTENER_RUNTIME
            .get_or_init(|| {
                Arc::new(Self {
                    state: Mutex::new(Http3ListenerRuntimeState::default()),
                })
            })
            .clone()
    }

    async fn validate_config(&self, context: Arc<WafContext>) -> Result<()> {
        let config = context.config_snapshot();
        let http3 = &config.http3_config;
        if !http3.enabled {
            return Ok(());
        }

        engine_tls::validate_http3_endpoint_config(http3)?;
        let requested_addr = http3.listen_addr.trim().to_string();
        let config_key = http3_config_key(http3)?;
        let guard = self.state.lock().await;
        let owned = guard
            .listener
            .as_ref()
            .map(|listener| listener.addr == requested_addr && listener.config_key == config_key)
            .unwrap_or(false);
        drop(guard);

        if !owned {
            UdpSocket::bind(&requested_addr).await.map_err(|err| {
                anyhow::anyhow!(
                    "HTTP/3 入口 {} 已被其他进程占用或无法监听: {}",
                    requested_addr,
                    err
                )
            })?;
        }

        Ok(())
    }

    async fn sync(&self, context: Arc<WafContext>, connection_semaphore: Arc<Semaphore>) -> Result<()> {
        let config = context.config_snapshot();
        let http3 = &config.http3_config;
        let mut guard = self.state.lock().await;
        let previous = guard.listener.take();
        drop(guard);

        if !http3.enabled {
            if let Some(listener) = previous {
                shutdown_http3_listener(listener).await;
            }
            context.set_http3_runtime("disabled", false, None, None);
            return Ok(());
        }

        let config_key = http3_config_key(http3)?;
        if let Some(existing) = previous {
            if existing.config_key == config_key {
                let listener_addr = existing.addr.clone();
                let mut guard = self.state.lock().await;
                guard.listener = Some(existing);
                drop(guard);
                context.set_http3_runtime("running", true, Some(listener_addr), None);
                return Ok(());
            }
            shutdown_http3_listener(existing).await;
        }

        let listener = spawn_http3_listener(http3, context.clone(), connection_semaphore).await?;
        let listener_addr = listener.addr.clone();
        let mut guard = self.state.lock().await;
        guard.listener = Some(listener);
        drop(guard);
        context.set_http3_runtime("running", true, Some(listener_addr), None);
        Ok(())
    }

    pub(super) async fn shutdown_all(&self, context: Arc<WafContext>) {
        let mut guard = self.state.lock().await;
        let previous = guard.listener.take();
        drop(guard);

        if let Some(listener) = previous {
            shutdown_http3_listener(listener).await;
        }
        context.set_http3_runtime("disabled", false, None, None);
    }
}

pub(crate) async fn validate_entry_listener_config(context: Arc<WafContext>) -> Result<()> {
    EntryListenerRuntime::global()
        .validate_config(context)
        .await
}

#[cfg(feature = "http3")]
pub(crate) async fn validate_http3_listener_config(context: Arc<WafContext>) -> Result<()> {
    Http3ListenerRuntime::global()
        .validate_config(context)
        .await
}

pub(crate) async fn sync_entry_listener_runtime(
    context: Arc<WafContext>,
    concurrency_limit: usize,
) -> Result<()> {
    EntryListenerRuntime::global()
        .sync(context, Arc::new(Semaphore::new(concurrency_limit.max(1))))
        .await
}

#[cfg(feature = "http3")]
pub(crate) async fn sync_http3_listener_runtime(
    context: Arc<WafContext>,
    concurrency_limit: usize,
) -> Result<()> {
    Http3ListenerRuntime::global()
        .sync(context, Arc::new(Semaphore::new(concurrency_limit.max(1))))
        .await
}

pub(crate) async fn shutdown_entry_listener_runtime() {
    EntryListenerRuntime::global().shutdown_all().await;
}

#[cfg(feature = "http3")]
pub(crate) async fn shutdown_http3_listener_runtime(context: Arc<WafContext>) {
    Http3ListenerRuntime::global().shutdown_all(context).await;
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

#[cfg(feature = "http3")]
fn http3_config_key(config: &crate::config::Http3Config) -> Result<String> {
    Ok(serde_json::to_string(config)?)
}

#[cfg(feature = "http3")]
async fn spawn_http3_listener(
    config: &crate::config::Http3Config,
    context: Arc<WafContext>,
    connection_semaphore: Arc<Semaphore>,
) -> Result<RunningHttp3Listener> {
    let endpoint = build_http3_endpoint(config)?
        .ok_or_else(|| anyhow::anyhow!("HTTP/3 listener was not started"))?;
    let addr_string = endpoint.local_addr()?.to_string();
    info!("HTTP/3 listener started on {}", addr_string);
    let config_key = http3_config_key(config)?;
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let task_addr = addr_string.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("HTTP/3 listener shutdown signal received for {}", task_addr);
                    endpoint.close(0u32.into(), b"listener shutdown");
                    break;
                }
                accept_result = endpoint.accept() => {
                    match accept_result {
                        Some(incoming) => {
                            match connection_semaphore.clone().try_acquire_owned() {
                                Ok(permit) => {
                                    let ctx = Arc::clone(&context);
                                    tokio::spawn(async move {
                                        if let Err(err) = handle_http3_quic_connection(ctx, incoming, incoming.remote_address(), permit).await {
                                            warn!("HTTP/3 connection handling failed: {}", err);
                                        }
                                    });
                                }
                                Err(_) => {
                                    warn!(
                                        "Dropping HTTP/3 connection on {} due to concurrency limit",
                                        task_addr
                                    );
                                }
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    Ok(RunningHttp3Listener {
        addr: addr_string,
        config_key,
        shutdown_tx,
        task,
    })
}

#[cfg(feature = "http3")]
async fn shutdown_http3_listener(listener: RunningHttp3Listener) {
    let _ = listener.shutdown_tx.send(()).await;
    let _ = listener.task.await;
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_tls_acceptor(
    context: &WafContext,
) -> Result<Option<tokio_rustls::TlsAcceptor>> {
    engine_tls::build_tls_acceptor(context)
}

#[cfg_attr(not(test), allow(dead_code))]
#[cfg(feature = "http3")]
pub(super) fn build_http3_endpoint(
    config: &crate::config::Http3Config,
) -> Result<Option<quinn::Endpoint>> {
    engine_tls::build_http3_endpoint(config)
}
