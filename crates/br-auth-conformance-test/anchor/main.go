package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type request struct {
	Op           string        `json:"op"`
	KeyB64       string        `json:"key_b64"`
	Token        string        `json:"token"`
	PlaintextB64 string        `json:"plaintext_b64"`
	Sealed       *sealedBearer `json:"sealed"`
}

type response struct {
	Op           string        `json:"op"`
	KVKey        string        `json:"kv_key,omitempty"`
	TokenHash    string        `json:"token_hash,omitempty"`
	Sealed       *sealedBearer `json:"sealed,omitempty"`
	PlaintextB64 string        `json:"plaintext_b64,omitempty"`
	Error        string        `json:"error,omitempty"`
}

func fail(msg string) {
	out, _ := json.Marshal(response{Error: msg})
	fmt.Println(string(out))
	os.Exit(0)
}

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(fmt.Sprintf("read stdin: %v", err))
	}
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		fail(fmt.Sprintf("parse request: %v", err))
	}

	switch req.Op {
	case "key":
		emit(response{
			Op:        "key",
			KVKey:     bearerTokenKVKey(req.Token),
			TokenHash: bearerTokenHash(req.Token),
		})
	case "seal":
		key, plaintext := decodeKeyAndPlaintext(req)
		sealed, err := sealBearer(key, req.Token, plaintext)
		if err != nil {
			fail(fmt.Sprintf("seal: %v", err))
		}
		emit(response{
			Op:        "seal",
			Sealed:    &sealed,
			KVKey:     bearerTokenKVKey(req.Token),
			TokenHash: bearerTokenHash(req.Token),
		})
	case "open":
		key := decodeKey(req)
		if req.Sealed == nil {
			fail("open requires a sealed value")
		}
		plaintext, err := openBearer(key, req.Token, *req.Sealed)
		if err != nil {
			emit(response{Op: "open", Error: fmt.Sprintf("aead open failed: %v", err)})
			return
		}
		emit(response{
			Op:           "open",
			PlaintextB64: base64.StdEncoding.EncodeToString(plaintext),
		})
	default:
		fail(fmt.Sprintf("unknown op %q", req.Op))
	}
}

func decodeKey(req request) []byte {
	key, err := base64.StdEncoding.DecodeString(req.KeyB64)
	if err != nil {
		fail(fmt.Sprintf("key_b64 is not base64: %v", err))
	}
	return key
}

func decodeKeyAndPlaintext(req request) ([]byte, []byte) {
	key := decodeKey(req)
	plaintext, err := base64.StdEncoding.DecodeString(req.PlaintextB64)
	if err != nil {
		fail(fmt.Sprintf("plaintext_b64 is not base64: %v", err))
	}
	return key, plaintext
}

func emit(resp response) {
	out, err := json.Marshal(resp)
	if err != nil {
		fail(fmt.Sprintf("marshal response: %v", err))
	}
	fmt.Println(string(out))
}
