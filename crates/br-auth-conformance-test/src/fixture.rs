use br_auth_contract::{BearerEntry, BearerSealKey};
use br_core_kernel::{Actor, ServiceAccountId, UserId};
use uuid::Uuid;

use crate::error::{ConformanceError, Result};

pub const SEAL_KEY_BYTES: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

pub const TOKEN: &str = "br-conformance-bearer-token-alpha";
pub const OTHER_TOKEN: &str = "br-conformance-bearer-token-beta";

pub fn seal_key() -> Result<BearerSealKey> {
    BearerSealKey::from_bytes(&SEAL_KEY_BYTES).map_err(ConformanceError::Contract)
}

pub fn human_entry() -> BearerEntry {
    BearerEntry {
        actor: Actor::Human(UserId::from(Uuid::from_u128(
            0x0193_8c1f_0000_7000_8000_0000_0000_0042,
        ))),
        token_id: Uuid::from_u128(0x0193_8c1f_0000_7000_8000_0000_0000_0007),
    }
}

pub fn service_entry() -> BearerEntry {
    BearerEntry {
        actor: Actor::Service(ServiceAccountId::from(Uuid::from_u128(
            0x0193_8c1f_0000_7000_8000_0000_0000_0099,
        ))),
        token_id: Uuid::from_u128(0x0193_8c1f_0000_7000_8000_0000_0000_0001),
    }
}

pub fn encode_entry(entry: &BearerEntry) -> Result<Vec<u8>> {
    serde_json::to_vec(entry).map_err(|e| ConformanceError::Encode(e.to_string()))
}
