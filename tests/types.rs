use nats_token::policy::{RenamingSubject, StringList, Subject, TagList};
use nats_token::ValidationResults;

#[test]
fn string_and_tag_lists_support_contains_and_remove() {
    let mut strings = StringList::default();
    strings.add(["a", "b"]);
    assert!(strings.contains("a"));
    strings.remove("a");
    assert!(!strings.contains("a"));

    let mut tags = TagList::default();
    tags.add([" Foo "]);
    assert!(tags.contains("foo"));
    tags.remove(" FOO ");
    assert!(!tags.contains("foo"));
}

#[test]
fn subject_validation_covers_empty_spaces_and_dots() {
    for value in ["", "foo bar", ".foo", "foo.", "foo..bar"] {
        let mut results = ValidationResults::default();
        Subject::from(value).validate(&mut results);
        assert!(results.is_blocking(false), "{value:?}");
    }
}

#[test]
fn renaming_subject_validation_requires_matching_wildcards() {
    let from = Subject::from("orders.*");
    let valid = RenamingSubject::from("archive.$1");
    let invalid = RenamingSubject::from("archive");
    let mut valid_results = ValidationResults::default();
    valid.validate(&from, &mut valid_results);
    assert!(!valid_results.is_blocking(false));
    let mut invalid_results = ValidationResults::default();
    invalid.validate(&from, &mut invalid_results);
    assert!(invalid_results.is_blocking(false));
}

#[test]
fn renaming_subject_rejects_out_of_range_reference() {
    let from = Subject::from("orders.*");
    let renamed = RenamingSubject::from("archive.$2");
    let mut results = ValidationResults::default();
    renamed.validate(&from, &mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn renaming_subject_suffix_requires_a_wildcard_token() {
    let mut results = ValidationResults::default();
    RenamingSubject::from("*.>").validate(&Subject::from("bar.*.*>"), &mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn renaming_subject_replaces_reference_wildcards() {
    let renamed = RenamingSubject::from("orders.$1.reply");
    assert_eq!(renamed.to_subject(), Subject::from("orders.*.reply"));
}
