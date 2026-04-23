use super::*;
use crate::core::engine_maintenance;

mod auto_audit;
mod maintenance;

const REQUEST_SEMAPHORE_CAPACITY: usize = 1024;
const CONNECTION_SEMAPHORE_CAPACITY: usize = 4096;

pub struct WafEngine {
    context: Arc<WafContext>,
    _shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: mpsc::Receiver<()>,
    connection_semaphore: Arc<Semaphore>,
    request_semaphore: Arc<Semaphore>,
}

impl WafEngine {
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing WAF engine...");

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let context = Arc::new(WafContext::new(config).await?);
        context.set_runtime_capacity_ceiling(
            REQUEST_SEMAPHORE_CAPACITY,
            CONNECTION_SEMAPHORE_CAPACITY,
        );

        Ok(Self {
            context,
            _shutdown_tx: shutdown_tx,
            shutdown_rx,
            connection_semaphore: Arc::new(Semaphore::new(CONNECTION_SEMAPHORE_CAPACITY)),
            request_semaphore: Arc::new(Semaphore::new(REQUEST_SEMAPHORE_CAPACITY)),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        let startup_config = self.context.config_snapshot();
        info!("WAF engine started");
        info!("Dynamic request limit set to {}", self.context.runtime_request_limit());
        info!(
            "Dynamic connection limit set to {}",
            self.context.runtime_connection_limit()
        );

        if let Some(l4_inspector) = self.context.l4_inspector() {
            l4_inspector.start(self.context.as_ref()).await?;
        }

        self.context
            .http_processor
            .start(self.context.as_ref())
            .await?;
        self.context.refresh_ai_temp_policies().await?;
        self.context.refresh_ai_route_profiles().await?;
        let context = Arc::clone(&self.context);
        tokio::spawn(async move {
            let _ = context.refresh_server_public_ip_allowlist(true).await;
        });
        let verifier = self.context.bot_ip_verifier();
        let provider_config = self.context.bot_provider_config();
        let store = self.context.sqlite_store.as_ref().cloned();
        tokio::spawn(async move {
            crate::core::bot_verifier::run_bot_ip_refresh_loop(verifier, provider_config, store)
                .await;
        });

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
            engine_maintenance::run_upstream_healthcheck_loop(context).await;
        });

        let context = Arc::clone(&self.context);
        tokio::spawn(async move {
            engine_maintenance::run_auto_tuning_loop(context).await;
        });

        if let Some(store) = self.context.sqlite_store.as_ref().cloned() {
            let fallback_config = startup_config.clone();
            tokio::spawn(async move {
                engine_maintenance::run_safeline_auto_sync_loop(store, fallback_config).await;
            });
        }

        let maintenance_interval = startup_config.maintenance_interval_secs.max(5);
        let mut maintenance =
            tokio::time::interval(tokio::time::Duration::from_secs(maintenance_interval));

        let mut shutdown_senders = Vec::new();
        let mut udp_listener_addresses = Vec::new();

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

        for (addr, socket) in udp_listener_addresses {
            info!("UDP inspection listener started on {}", addr);
            let context = Arc::clone(&self.context);
            let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
            let request_semaphore = Arc::clone(&self.request_semaphore);

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
                                    if let Some(permit) = crate::core::engine::runtime::acquire_permit_auto(
                                        context.as_ref(),
                                        request_semaphore.clone(),
                                        peer_addr,
                                        "UDP request",
                                    ).await {
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
                                    } else {
                                        warn!(
                                            "Dropping UDP datagram from {} due to dynamic concurrency limit",
                                            peer_addr
                                        );
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

        info!(
            "Successfully started {} listener task(s)",
            shutdown_senders.len()
        );

        let entry_runtime = EntryListenerRuntime::global();
        entry_runtime
            .sync(
                Arc::clone(&self.context),
                Arc::clone(&self.connection_semaphore),
                Arc::clone(&self.request_semaphore),
            )
            .await?;
        #[cfg(feature = "http3")]
        super::sync_http3_listener_runtime(
            Arc::clone(&self.context),
            self.connection_limit(),
            self.context.runtime_request_limit(),
        )
        .await?;

        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    for (_, shutdown_tx) in &shutdown_senders {
                        let _ = shutdown_tx.send(()).await;
                    }
                    super::shutdown_entry_listener_runtime().await;
                    #[cfg(feature = "http3")]
                    super::shutdown_http3_listener_runtime(Arc::clone(&self.context)).await;
                    self.context.shutdown_storage().await?;
                    break Ok(());
                }
                _ = maintenance.tick() => {
                    self.run_maintenance().await;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C received, shutting down");
                    for (_, shutdown_tx) in &shutdown_senders {
                        let _ = shutdown_tx.send(()).await;
                    }
                    super::shutdown_entry_listener_runtime().await;
                    #[cfg(feature = "http3")]
                    super::shutdown_http3_listener_runtime(Arc::clone(&self.context)).await;
                    self.context.shutdown_storage().await?;
                    break Ok(());
                }
            }
        }
    }

    fn connection_limit(&self) -> usize {
        self.context.runtime_connection_limit()
    }
}
