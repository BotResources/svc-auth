pub const BEARER_TOKENS_KEY_PREFIX: &str = "identity/bearer_tokens/";

pub fn bearer_token_kv_key(token: &str) -> String {
    format!(
        "{BEARER_TOKENS_KEY_PREFIX}{}",
        br_core_auth::bearer_token_key(token)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_key_is_prefix_plus_known_sha256_vector() {
        assert_eq!(
            bearer_token_kv_key("abc"),
            "identity/bearer_tokens/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn kv_key_starts_with_the_prefix() {
        assert!(bearer_token_kv_key("any-token").starts_with(BEARER_TOKENS_KEY_PREFIX));
    }

    #[test]
    fn kv_key_reuses_core_auth_hash() {
        let token = "bearer-secret-1";
        let expected = format!(
            "{BEARER_TOKENS_KEY_PREFIX}{}",
            br_core_auth::bearer_token_key(token)
        );
        assert_eq!(bearer_token_kv_key(token), expected);
    }
}
