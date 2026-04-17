use super::*;

#[tokio::test]
async fn test_sqlite_store_manages_local_certificates() {
    let path = unique_test_db_path("local_certificates");
    let store = SqliteStore::new(path, true).await.unwrap();

    let certificate_id = store
        .insert_local_certificate(&LocalCertificateUpsert {
            name: "prod wildcard".to_string(),
            domains: vec!["example.com".to_string(), "*.example.com".to_string()],
            issuer: "Let's Encrypt".to_string(),
            valid_from: Some(1_700_000_000),
            valid_to: Some(1_800_000_000),
            source_type: "manual".to_string(),
            provider_remote_id: Some("31".to_string()),
            provider_remote_domains: vec!["example.com".to_string(), "*.example.com".to_string()],
            last_remote_fingerprint: Some("fp31".to_string()),
            sync_status: "synced".to_string(),
            sync_message: "ok".to_string(),
            auto_sync_enabled: true,
            trusted: true,
            expired: false,
            notes: "initial import".to_string(),
            last_synced_at: Some(1_700_000_100),
        })
        .await
        .unwrap();

    let loaded = store
        .load_local_certificate(certificate_id)
        .await
        .unwrap()
        .unwrap();
    let domains: Vec<String> = serde_json::from_str(&loaded.domains_json).unwrap();
    assert_eq!(loaded.name, "prod wildcard");
    assert_eq!(domains, vec!["example.com", "*.example.com"]);
    assert_eq!(loaded.provider_remote_id.as_deref(), Some("31"));
    assert!(loaded.trusted);

    store
        .upsert_local_certificate_secret(
            certificate_id,
            "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
            "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
        )
        .await
        .unwrap();
    let secret = store
        .load_local_certificate_secret(certificate_id)
        .await
        .unwrap()
        .unwrap();
    assert!(secret.certificate_pem.contains("BEGIN CERTIFICATE"));
    assert!(secret.private_key_pem.contains("BEGIN PRIVATE KEY"));

    let updated = store
        .update_local_certificate(
            certificate_id,
            &LocalCertificateUpsert {
                name: "prod wildcard v2".to_string(),
                domains: vec!["example.com".to_string()],
                issuer: "Let's Encrypt".to_string(),
                valid_from: Some(1_700_000_000),
                valid_to: Some(1_900_000_000),
                source_type: "safeline".to_string(),
                provider_remote_id: Some("32".to_string()),
                provider_remote_domains: vec!["example.com".to_string()],
                last_remote_fingerprint: Some("fp32".to_string()),
                sync_status: "synced".to_string(),
                sync_message: "updated".to_string(),
                auto_sync_enabled: false,
                trusted: true,
                expired: false,
                notes: "rotated".to_string(),
                last_synced_at: Some(1_700_000_200),
            },
        )
        .await
        .unwrap();
    assert!(updated);

    let listed = store.list_local_certificates().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "prod wildcard v2");
    assert_eq!(listed[0].provider_remote_id.as_deref(), Some("32"));

    store
        .upsert_local_certificate_secret(
            certificate_id,
            "-----BEGIN CERTIFICATE-----\nCERT-V2\n-----END CERTIFICATE-----",
            "-----BEGIN PRIVATE KEY-----\nKEY-V2\n-----END PRIVATE KEY-----",
        )
        .await
        .unwrap();
    let updated_secret = store
        .load_local_certificate_secret(certificate_id)
        .await
        .unwrap()
        .unwrap();
    assert!(updated_secret.certificate_pem.contains("CERT-V2"));

    let deleted = store
        .delete_local_certificate(certificate_id)
        .await
        .unwrap();
    assert!(deleted);
    assert!(store
        .load_local_certificate(certificate_id)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .load_local_certificate_secret(certificate_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_sqlite_store_manages_local_sites_and_sync_links() {
    let path = unique_test_db_path("local_sites");
    let store = SqliteStore::new(path, true).await.unwrap();

    let certificate_id = store
        .insert_local_certificate(&LocalCertificateUpsert {
            name: "portal cert".to_string(),
            domains: vec!["portal.example.com".to_string()],
            issuer: "Acme CA".to_string(),
            valid_from: None,
            valid_to: None,
            source_type: "manual".to_string(),
            provider_remote_id: None,
            provider_remote_domains: Vec::new(),
            last_remote_fingerprint: None,
            sync_status: "idle".to_string(),
            sync_message: String::new(),
            auto_sync_enabled: false,
            trusted: false,
            expired: false,
            notes: String::new(),
            last_synced_at: None,
        })
        .await
        .unwrap();

    let site_id = store
        .insert_local_site(&LocalSiteUpsert {
            name: "Portal".to_string(),
            primary_hostname: "portal.example.com".to_string(),
            hostnames: vec![
                "portal.example.com".to_string(),
                "www.portal.example.com".to_string(),
            ],
            listen_ports: vec!["80".to_string(), "443".to_string()],
            upstreams: vec!["http://127.0.0.1:8080".to_string()],
            safeline_intercept: None,
            enabled: true,
            tls_enabled: true,
            local_certificate_id: Some(certificate_id),
            source: "manual".to_string(),
            sync_mode: "bidirectional".to_string(),
            notes: "production".to_string(),
            last_synced_at: Some(1_700_000_300),
        })
        .await
        .unwrap();

    let loaded_site = store.load_local_site(site_id).await.unwrap().unwrap();
    let hostnames: Vec<String> = serde_json::from_str(&loaded_site.hostnames_json).unwrap();
    let listen_ports: Vec<String> = serde_json::from_str(&loaded_site.listen_ports_json).unwrap();
    assert_eq!(loaded_site.primary_hostname, "portal.example.com");
    assert_eq!(hostnames.len(), 2);
    assert_eq!(listen_ports, vec!["80", "443"]);
    assert_eq!(loaded_site.local_certificate_id, Some(certificate_id));

    let updated = store
        .update_local_site(
            site_id,
            &LocalSiteUpsert {
                name: "Portal Main".to_string(),
                primary_hostname: "portal.example.com".to_string(),
                hostnames: vec!["portal.example.com".to_string()],
                listen_ports: vec!["443".to_string()],
                upstreams: vec![
                    "http://127.0.0.1:8080".to_string(),
                    "http://127.0.0.1:8081".to_string(),
                ],
                safeline_intercept: None,
                enabled: true,
                tls_enabled: true,
                local_certificate_id: Some(certificate_id),
                source: "safeline".to_string(),
                sync_mode: "remote_to_local".to_string(),
                notes: "synced".to_string(),
                last_synced_at: Some(1_700_000_400),
            },
        )
        .await
        .unwrap();
    assert!(updated);

    store
        .upsert_site_sync_link(&SiteSyncLinkUpsert {
            local_site_id: site_id,
            provider: "safeline".to_string(),
            remote_site_id: "remote-1".to_string(),
            remote_site_name: "portal.example.com".to_string(),
            remote_cert_id: Some("31".to_string()),
            sync_mode: "remote_to_local".to_string(),
            last_local_hash: Some("local-a".to_string()),
            last_remote_hash: Some("remote-a".to_string()),
            last_error: None,
            last_synced_at: Some(1_700_000_500),
        })
        .await
        .unwrap();

    store
        .upsert_site_sync_link(&SiteSyncLinkUpsert {
            local_site_id: site_id,
            provider: "safeline".to_string(),
            remote_site_id: "remote-2".to_string(),
            remote_site_name: "portal-new.example.com".to_string(),
            remote_cert_id: Some("32".to_string()),
            sync_mode: "bidirectional".to_string(),
            last_local_hash: Some("local-b".to_string()),
            last_remote_hash: Some("remote-b".to_string()),
            last_error: Some("conflict".to_string()),
            last_synced_at: Some(1_700_000_600),
        })
        .await
        .unwrap();

    let links = store.list_site_sync_links().await.unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].remote_site_id, "remote-2");
    assert_eq!(links[0].remote_cert_id.as_deref(), Some("32"));
    assert_eq!(links[0].last_error.as_deref(), Some("conflict"));

    let deleted_link = store.delete_site_sync_link(links[0].id).await.unwrap();
    assert!(deleted_link);
    assert!(store.list_site_sync_links().await.unwrap().is_empty());

    let deleted_site = store.delete_local_site(site_id).await.unwrap();
    assert!(deleted_site);
    assert!(store.load_local_site(site_id).await.unwrap().is_none());

    let cert_after_site_delete = store
        .load_local_certificate(certificate_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cert_after_site_delete.id, certificate_id);
}
