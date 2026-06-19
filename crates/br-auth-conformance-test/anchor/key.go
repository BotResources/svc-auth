package main

import (
	"crypto/sha256"
	"encoding/hex"
)

const bearerTokensKeyPrefix = "identity/bearer_tokens/"

func bearerTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func bearerTokenKVKey(token string) string {
	return bearerTokensKeyPrefix + bearerTokenHash(token)
}
