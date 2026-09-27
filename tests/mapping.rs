use nats_token::policy::{Mapping, MappingValidation, Subject, WeightedMapping};
use nats_token::{Account, ValidationResults};

#[test]
fn account_add_mapping_updates_collection_and_wire_serialization() {
    let mut account = Account::default();
    let destinations = vec![
        WeightedMapping::new("east", 60),
        WeightedMapping::new("west", 40),
    ];

    account.add_mapping(Subject::from("orders"), destinations.clone());

    assert_eq!(account.mappings[&Subject::from("orders")], destinations);
    assert_eq!(
        serde_json::to_value(&account).unwrap()["mappings"]["orders"],
        serde_json::json!([
            {"subject": "east", "weight": 60},
            {"subject": "west", "weight": 40}
        ])
    );
}

#[test]
fn mapping_rejects_total_weight_above_one_hundred() {
    let mut mapping = Mapping::default();
    mapping.insert(
        Subject::from("orders"),
        vec![
            WeightedMapping::new("east", 60),
            WeightedMapping::new("west", 50),
        ],
    );
    let mut results = ValidationResults::default();
    mapping.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn mapping_rejects_cluster_weight_overflow() {
    let mut mapping = Mapping::default();
    let mut first = WeightedMapping::new("east-a", 60);
    first.cluster = "cluster-a".into();
    let mut second = WeightedMapping::new("east-b", 50);
    second.cluster = "cluster-a".into();
    mapping.insert(Subject::from("orders"), vec![first, second]);
    let mut results = ValidationResults::default();
    mapping.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn mapping_allows_one_hundred_percent_per_cluster_and_unclustered() {
    let mut mapping = Mapping::default();
    let mut destinations = Vec::new();
    for (subject, cluster) in [("east", "a"), ("west", "b"), ("backup", "c")] {
        let mut destination = WeightedMapping::new(subject, 100);
        destination.cluster = cluster.into();
        destinations.push(destination);
    }
    destinations.push(WeightedMapping::new("default", 100));
    mapping.insert(Subject::from("orders"), destinations);

    let mut results = ValidationResults::default();
    mapping.validate(&mut results);
    assert!(results.is_empty());
}

#[test]
fn mapping_detects_u8_sum_overflow() {
    for cluster in [None, Some("a")] {
        let mut mapping = Mapping::default();
        let destinations = ["east", "west", "backup"]
            .into_iter()
            .map(|subject| {
                let mut destination = WeightedMapping::new(subject, 90);
                destination.cluster = cluster.unwrap_or_default().into();
                destination
            })
            .collect();
        mapping.insert(Subject::from("orders"), destinations);

        let mut results = ValidationResults::default();
        mapping.validate(&mut results);
        assert!(results.is_blocking(false), "cluster={cluster:?}");
    }
}

#[test]
fn mapping_allows_default_weight_and_valid_subjects() {
    let mut mapping = Mapping::default();
    mapping.insert(
        Subject::from("orders"),
        vec![WeightedMapping::new("east", 0)],
    );
    let mut results = ValidationResults::default();
    mapping.validate(&mut results);
    assert!(!results.is_blocking(false));
    assert_eq!(mapping[&Subject::from("orders")][0].effective_weight(), 100);
}
