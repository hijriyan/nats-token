//! Accumulated semantic findings, with optional enforcement of time-dependent checks.

/// One semantic validation finding, classified as blocking, time-dependent, or advisory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    /// Human-readable explanation of the finding.
    pub description: String,
    /// Whether the issue blocks use regardless of time-check policy.
    pub blocking: bool,
    /// Whether the finding is time-dependent and optionally blocking.
    pub time_check: bool,
}

/// Accumulated semantic findings. Validators append without clearing existing issues.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationResults {
    /// Findings in insertion order; callers may inspect or clear them explicitly.
    pub issues: Vec<ValidationIssue>,
}

impl ValidationResults {
    /// Append an unconditionally blocking semantic error.
    pub fn add_error(&mut self, description: impl Into<String>) {
        self.issues.push(ValidationIssue {
            description: description.into(),
            blocking: true,
            time_check: false,
        });
    }

    /// Append a time-dependent finding, blocking only when callers opt into time checks.
    pub fn add_time_check(&mut self, description: impl Into<String>) {
        self.issues.push(ValidationIssue {
            description: description.into(),
            blocking: false,
            time_check: true,
        });
    }

    /// Append a nonblocking advisory finding.
    pub fn add_warning(&mut self, description: impl Into<String>) {
        self.issues.push(ValidationIssue {
            description: description.into(),
            blocking: false,
            time_check: false,
        });
    }

    /// Return whether any error blocks use, optionally treating time findings as blocking too.
    pub fn is_blocking(&self, include_time_checks: bool) -> bool {
        self.issues
            .iter()
            .any(|issue| issue.blocking || (include_time_checks && issue.time_check))
    }

    /// Return whether the collection or wire value has no entries or content.
    pub fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }

    /// Collect references to unconditional blocking findings; time findings are excluded.
    pub fn errors(&self) -> Vec<&ValidationIssue> {
        self.issues.iter().filter(|issue| issue.blocking).collect()
    }

    /// Collect references to all nonblocking findings, including time checks.
    pub fn warnings(&self) -> Vec<&ValidationIssue> {
        self.issues.iter().filter(|issue| !issue.blocking).collect()
    }
}
