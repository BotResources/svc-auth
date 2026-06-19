use br_core_kernel::Actor;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BearerEntry {
    pub actor: Actor,
    pub token_id: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use br_core_kernel::{ServiceAccountId, UserId};

    #[test]
    fn human_entry_serde_roundtrip() {
        let entry = BearerEntry {
            actor: Actor::Human(UserId::from(Uuid::from_u128(0x42))),
            token_id: Uuid::from_u128(0x7),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: BearerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn service_entry_serde_roundtrip() {
        let entry = BearerEntry {
            actor: Actor::Service(ServiceAccountId::from(Uuid::from_u128(0x99))),
            token_id: Uuid::from_u128(0x1),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: BearerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn entry_rejects_unknown_field() {
        let json = serde_json::json!({
            "actor": { "kind": "human", "id": Uuid::nil().to_string() },
            "token_id": Uuid::nil().to_string(),
            "evil": true,
        });
        assert!(serde_json::from_value::<BearerEntry>(json).is_err());
    }
}
