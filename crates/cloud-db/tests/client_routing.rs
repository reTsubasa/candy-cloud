use cloud_db::client_routing::{
    select_nodes, ClientNodeCandidate, ClientRoutingError, MAX_CLIENT_NODE_BACKUPS,
};
use uuid::Uuid;

fn candidate(region: &str, node_id: u128, endpoint_id: u128) -> ClientNodeCandidate {
    ClientNodeCandidate {
        node_id: Uuid::from_u128(node_id),
        node_key_id: Uuid::new_v4(),
        endpoint_id: Uuid::from_u128(endpoint_id),
        endpoint: "edge.example.test:443".into(),
        region: region.into(),
        server_name: "node.example.test".into(),
        server_cert_sha256: [9; 32],
    }
}

#[test]
fn node_selection_prefers_region_and_is_deterministic() {
    let result = select_nodes(
        vec![
            candidate("us-east", 3, 30),
            candidate("ap-southeast", 2, 20),
            candidate("ap-southeast", 1, 10),
            candidate("eu-west", 4, 40),
        ],
        Some("ap-southeast"),
        MAX_CLIENT_NODE_BACKUPS,
    )
    .unwrap();

    assert_eq!(result.primary.node_id, Uuid::from_u128(1));
    assert_eq!(
        result
            .backups
            .iter()
            .map(|node| node.node_id)
            .collect::<Vec<_>>(),
        vec![Uuid::from_u128(2), Uuid::from_u128(4)]
    );
}

#[test]
fn node_selection_uses_one_endpoint_per_node() {
    let result = select_nodes(
        vec![
            candidate("eu", 1, 20),
            candidate("ap", 1, 10),
            candidate("ap", 2, 30),
        ],
        None,
        1,
    )
    .unwrap();

    assert_eq!(result.primary.endpoint_id, Uuid::from_u128(10));
    assert_eq!(result.backups[0].node_id, Uuid::from_u128(2));
}

#[test]
fn node_selection_rejects_insufficient_backups_and_invalid_candidates() {
    assert_eq!(
        select_nodes(vec![candidate("ap", 1, 10)], None, 1),
        Err(ClientRoutingError::NoActiveNode)
    );

    let mut invalid = candidate("ap", 1, 10);
    invalid.server_cert_sha256 = [0; 32];
    assert_eq!(
        select_nodes(vec![invalid], None, 0),
        Err(ClientRoutingError::InvalidCandidate)
    );

    assert_eq!(
        select_nodes(
            vec![candidate("ap", 1, 10)],
            None,
            MAX_CLIENT_NODE_BACKUPS + 1
        ),
        Err(ClientRoutingError::InvalidBackupCount)
    );
}

#[tokio::test]
async fn active_candidates_rejects_missing_scope_before_database_access() {
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .connect_lazy("mysql://unused:unused@127.0.0.1/unused")
        .unwrap();
    let repository = cloud_db::client_routing::ClientNodeRepository::new(pool);
    assert_eq!(
        repository.active_candidates(Uuid::nil()).await,
        Err(ClientRoutingError::InvalidScope)
    );
}
