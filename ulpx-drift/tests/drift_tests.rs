use std::collections::BTreeMap;
use ulpx_core::event::EventId;
use ulpx_core::parser::ParserVersion;
use ulpx_drift::{DriftDetector, DriftProfile, DriftType};
use ulpx_ir::model::{IrType, IrValue};
use ulpx_mapping::model::{CanonicalEvent, CanonicalField, Confidence, FieldProvenance};

fn mock_event(
    id_str: &str,
    action_val: Option<&str>,
    unmapped_keys: Vec<&str>,
    parser_id: &str,
    source_field: &str,
) -> CanonicalEvent {
    let mut unmapped = BTreeMap::new();
    for k in unmapped_keys {
        unmapped.insert(
            k.to_string(),
            IrValue {
                ty: IrType::String("mock".to_string()),
                span: None,
            },
        );
    }

    let action = action_val.map(|v| CanonicalField {
        value: v.to_string(),
        provenance: FieldProvenance {
            source_field: source_field.to_string(),
            span: None,
            transformations: vec![],
            rule_id: "rule1".to_string(),
            confidence: Confidence::Certain,
            parser_id: parser_id.to_string(),
            parser_version: ParserVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
        },
    });

    CanonicalEvent {
        event_id: EventId::new(id_str).unwrap(),
        parser_id: parser_id.to_string(),
        parser_version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        raw_bytes: vec![],
        timestamp: None,
        source_ip: None,
        source_hostname: None,
        dest_ip: None,
        dest_hostname: None,
        severity: None,
        message: None,
        action,
        unmapped,
        abstentions: vec![],
    }
}

#[test]
fn test_vocabulary_drift() {
    let mut base_profile = DriftProfile::new("source1", 0, 100);
    // Baseline: mostly "allow"
    for i in 0..90 {
        base_profile.observe(&mock_event(
            &format!("ev{}", i),
            Some("allow"),
            vec![],
            "p1",
            "raw_action",
        ));
    }
    for i in 90..100 {
        base_profile.observe(&mock_event(
            &format!("ev{}", i),
            Some("deny"),
            vec![],
            "p1",
            "raw_action",
        ));
    }

    let mut curr_profile = DriftProfile::new("source1", 100, 200);
    // Current: "permit" instead of "allow"
    for i in 100..190 {
        curr_profile.observe(&mock_event(
            &format!("ev{}", i),
            Some("permit"),
            vec![],
            "p1",
            "raw_action",
        ));
    }
    for i in 190..200 {
        curr_profile.observe(&mock_event(
            &format!("ev{}", i),
            Some("deny"),
            vec![],
            "p1",
            "raw_action",
        ));
    }

    let detector = DriftDetector::default();
    let report = detector.detect(&base_profile, &curr_profile);

    assert!(report.has_drift());
    assert_eq!(report.vocabulary_drift.len(), 1);
    let vocab_drift = &report.vocabulary_drift[0];
    assert_eq!(vocab_drift.field, "action");
    assert!(vocab_drift.values_added.contains(&"permit".to_string()));
    assert!(vocab_drift.values_removed.contains(&"allow".to_string()));
}

#[test]
fn test_structural_schema_format_drift() {
    let mut base_profile = DriftProfile::new("source1", 0, 100);
    for i in 0..100 {
        base_profile.observe(&mock_event(
            &format!("ev{}", i),
            None,
            vec!["f1", "f2"],
            "p1",
            "raw_action",
        ));
    }

    let mut curr_profile = DriftProfile::new("source1", 100, 200);
    for i in 100..200 {
        // format changed to p2, structural changed to f1, f3
        curr_profile.observe(&mock_event(
            &format!("ev{}", i),
            None,
            vec!["f1", "f3"],
            "p2",
            "raw_action",
        ));
    }

    let detector = DriftDetector::default();
    let report = detector.detect(&base_profile, &curr_profile);

    assert!(report.has_drift());

    // Format drift
    assert!(report
        .format_drift
        .iter()
        .any(|d| d.item == "p1" && matches!(d.drift_type, DriftType::Removed)));
    assert!(report
        .format_drift
        .iter()
        .any(|d| d.item == "p2" && matches!(d.drift_type, DriftType::Added)));

    // Structural drift
    assert!(report
        .structural_drift
        .iter()
        .any(|d| d.item == "f2" && matches!(d.drift_type, DriftType::Removed)));
    assert!(report
        .structural_drift
        .iter()
        .any(|d| d.item == "f3" && matches!(d.drift_type, DriftType::Added)));
}

#[test]
fn test_volume_drift() {
    let mut base_profile = DriftProfile::new("s1", 0, 100);
    for i in 0..100 {
        base_profile.observe(&mock_event(
            &format!("ev{}", i),
            None,
            vec![],
            "p1",
            "raw_action",
        ));
    }

    let mut curr_profile = DriftProfile::new("s1", 100, 200);
    for i in 100..200 {
        curr_profile.observe(&mock_event(
            &format!("ev{}", i),
            None,
            vec![],
            "p1",
            "raw_action",
        ));
    }
    // No volume drift (100 -> 100)
    let detector = DriftDetector::default();
    let r1 = detector.detect(&base_profile, &curr_profile);
    assert!(r1.volume_drift.is_none());

    // Big volume drift (100 -> 250)
    let mut high_profile = DriftProfile::new("s1", 200, 300);
    for i in 0..250 {
        high_profile.observe(&mock_event(
            &format!("ev{}", i),
            None,
            vec![],
            "p1",
            "raw_action",
        ));
    }
    let r2 = detector.detect(&base_profile, &high_profile);
    assert!(r2.volume_drift.is_some());
    assert_eq!(r2.volume_drift.as_ref().unwrap().percent_change, 1.5); // (250 - 100)/100 = 1.5
}

#[test]
fn test_semantic_drift() {
    let mut base_profile = DriftProfile::new("s1", 0, 100);
    for i in 0..100 {
        base_profile.observe(&mock_event(
            &format!("ev{}", i),
            Some("allow"),
            vec![],
            "p1",
            "raw_action",
        ));
    }

    let mut curr_profile = DriftProfile::new("s1", 100, 200);
    for i in 100..200 {
        curr_profile.observe(&mock_event(
            &format!("ev{}", i),
            Some("allow"),
            vec![],
            "p1",
            "different_raw_action",
        ));
    }

    let detector = DriftDetector::default();
    let r = detector.detect(&base_profile, &curr_profile);
    assert!(r.has_drift());
    // The semantic mapping from "raw_action->action" is removed, "different_raw_action->action" is added
    assert!(r
        .semantic_drift
        .iter()
        .any(|d| d.item == "raw_action->action" && matches!(d.drift_type, DriftType::Removed)));
    assert!(r
        .semantic_drift
        .iter()
        .any(|d| d.item == "different_raw_action->action"
            && matches!(d.drift_type, DriftType::Added)));
}

#[test]
fn test_schema_drift() {
    let mut base_profile = DriftProfile::new("s1", 0, 100);
    for i in 0..100 {
        base_profile.observe(&mock_event(
            &format!("ev{}", i),
            Some("allow"),
            vec![],
            "p1",
            "raw_action",
        ));
    }

    let mut curr_profile = DriftProfile::new("s1", 100, 200);
    for i in 100..200 {
        curr_profile.observe(&mock_event(
            &format!("ev{}", i),
            None, // action canonical field removed
            vec![],
            "p1",
            "raw_action",
        ));
    }

    let detector = DriftDetector::default();
    let r = detector.detect(&base_profile, &curr_profile);
    assert!(r.has_drift());
    // Schema drift: action was removed
    assert!(r
        .schema_drift
        .iter()
        .any(|d| d.item == "action" && matches!(d.drift_type, DriftType::Removed)));
}
