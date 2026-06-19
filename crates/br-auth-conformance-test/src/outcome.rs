use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckId {
    GoSealOpensThroughLib,
    RustSealOpensInGo,
    KvKeyAgrees,
    SealedWireDeserializes,
    TamperedCiphertextFails,
    RelocatedSealFails,
    RidesPublishedLanguageConsumer,
    DirectoryPrefixIgnoresBearer,
    UndecodableBearerValueFailsClosed,
}

impl CheckId {
    pub fn code(self) -> &'static str {
        match self {
            CheckId::GoSealOpensThroughLib => "x1",
            CheckId::RustSealOpensInGo => "x2",
            CheckId::KvKeyAgrees => "x3",
            CheckId::SealedWireDeserializes => "x4",
            CheckId::TamperedCiphertextFails => "n1",
            CheckId::RelocatedSealFails => "n2",
            CheckId::RidesPublishedLanguageConsumer => "k1",
            CheckId::DirectoryPrefixIgnoresBearer => "k2",
            CheckId::UndecodableBearerValueFailsClosed => "k3",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "x1" => Some(CheckId::GoSealOpensThroughLib),
            "x2" => Some(CheckId::RustSealOpensInGo),
            "x3" => Some(CheckId::KvKeyAgrees),
            "x4" => Some(CheckId::SealedWireDeserializes),
            "n1" => Some(CheckId::TamperedCiphertextFails),
            "n2" => Some(CheckId::RelocatedSealFails),
            "k1" => Some(CheckId::RidesPublishedLanguageConsumer),
            "k2" => Some(CheckId::DirectoryPrefixIgnoresBearer),
            "k3" => Some(CheckId::UndecodableBearerValueFailsClosed),
            _ => None,
        }
    }
}

impl fmt::Display for CheckId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
    Skipped,
}

impl CheckStatus {
    pub fn code(self) -> &'static str {
        match self {
            CheckStatus::Pass => "pass",
            CheckStatus::Fail => "fail",
            CheckStatus::Skipped => "skipped",
        }
    }
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

#[derive(Debug, Clone)]
pub struct CheckOutcome {
    pub id: CheckId,
    pub status: CheckStatus,
    pub expected: String,
    pub observed: String,
    pub detail: Option<String>,
}

impl CheckOutcome {
    pub fn pass(id: CheckId, expected: impl Into<String>, observed: impl Into<String>) -> Self {
        Self {
            id,
            status: CheckStatus::Pass,
            expected: expected.into(),
            observed: observed.into(),
            detail: None,
        }
    }

    pub fn fail(
        id: CheckId,
        expected: impl Into<String>,
        observed: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id,
            status: CheckStatus::Fail,
            expected: expected.into(),
            observed: observed.into(),
            detail: Some(detail.into()),
        }
    }

    pub fn skipped(id: CheckId, detail: impl Into<String>) -> Self {
        Self {
            id,
            status: CheckStatus::Skipped,
            expected: String::new(),
            observed: String::new(),
            detail: Some(detail.into()),
        }
    }

    pub fn is_pass(&self) -> bool {
        self.status == CheckStatus::Pass
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConformanceReport {
    pub outcomes: Vec<CheckOutcome>,
}

impl ConformanceReport {
    pub fn push(&mut self, outcome: CheckOutcome) {
        self.outcomes.push(outcome);
    }

    pub fn passed(&self) -> usize {
        self.count(CheckStatus::Pass)
    }

    pub fn failed(&self) -> usize {
        self.count(CheckStatus::Fail)
    }

    pub fn skipped(&self) -> usize {
        self.count(CheckStatus::Skipped)
    }

    fn count(&self, status: CheckStatus) -> usize {
        self.outcomes.iter().filter(|o| o.status == status).count()
    }

    pub fn is_conformant(&self) -> bool {
        self.failed() == 0
    }
}
