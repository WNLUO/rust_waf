use super::*;
use crate::core::engine_maintenance;

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
            engine_maintenance::run_upstream_healthcheck_loop(context).await;
        });

        let context = Arc::clone(&self.context);
        tokio::spawn(async move {
            engine_maintenance::run_auto_tuning_loop(context).await;
        });

        let context = Arc::clone(&self.context);
        tokio::spawn(async move {
            engine_maintenance::run_trusted_cdn_sync_loop(context).await;
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
        #[cfg(feature = "http3")]
        super::sync_http3_listener_runtime(
            Arc::clone(&self.context),
            startup_config.max_concurrent_tasks,
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

    async fn run_maintenance(&self) {
        if let Err(err) = self.context.refresh_rules_from_storage().await {
            warn!("Failed to refresh rules from SQLite: {}", err);
        }

        if let Some(store) = self.context.sqlite_store.as_ref() {
            let storage_policy = self.context.config_snapshot().storage_policy;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let thresholds = [
                (
                    "security events",
                    store
                        .purge_old_security_events(
                            now.saturating_sub(
                                (storage_policy.security_event_retention_days * 24 * 3600) as i64,
                            ),
                        )
                        .await,
                ),
                (
                    "behavior events",
                    store
                        .purge_old_behavior_events(
                            now.saturating_sub(
                                (storage_policy.behavior_event_retention_days * 24 * 3600) as i64,
                            ),
                        )
                        .await,
                ),
                (
                    "behavior sessions",
                    store
                        .purge_old_behavior_sessions(
                            now.saturating_sub(
                                (storage_policy.behavior_session_retention_days * 24 * 3600)
                                    as i64,
                            ),
                        )
                        .await,
                ),
                (
                    "fingerprint profiles",
                    store
                        .purge_old_fingerprint_profiles(
                            now.saturating_sub(
                                (storage_policy.fingerprint_profile_retention_days * 24 * 3600)
                                    as i64,
                            ),
                        )
                        .await,
                ),
                (
                    "AI audit reports",
                    store
                        .purge_old_ai_audit_reports(
                            now.saturating_sub(
                                (storage_policy.ai_audit_report_retention_days * 24 * 3600)
                                    as i64,
                            ),
                        )
                        .await,
                ),
            ];
            for (label, result) in thresholds {
                match result {
                    Ok(removed) if removed > 0 => {
                        debug!("Maintenance purged {} stale {}", removed, label);
                    }
                    Ok(_) => {}
                    Err(err) => warn!("Failed to purge stale {}: {}", label, err),
                }
            }
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
