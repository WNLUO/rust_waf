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

pub(super) struct EntryListenerRuntime {
    state: Mutex<EntryListenerRuntimeState>,
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

pub(crate) async fn validate_entry_listener_config(context: Arc<WafContext>) -> Result<()> {
    EntryListenerRuntime::global()
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
