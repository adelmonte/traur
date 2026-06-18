use serde::Serialize;

/// A signal (finding) emitted by a feature during analysis.
///
/// traur no longer computes a trust score or tier — it reports the raw findings.
/// `points` and `is_override_gate` are retained as internal metadata that some
/// features still populate, but they no longer affect output and are not
/// serialized.
#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub id: String,
    pub category: SignalCategory,
    // Retained as inert metadata (features still populate these); no longer
    // used for ranking and not serialized.
    #[serde(skip)]
    #[allow(dead_code)]
    pub points: u32,
    pub description: String,
    #[serde(skip)]
    #[allow(dead_code)]
    pub is_override_gate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_line: Option<String>,
}

/// Coarse grouping tag for a signal. Used for display grouping and for the
/// `traur ignore --category` filter. Carries no weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SignalCategory {
    Metadata,
    Pkgbuild,
    Behavioral,
    Temporal,
}

/// Complete result of scanning a package: just the flat list of findings.
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub package: String,
    pub signals: Vec<Signal>,
}
