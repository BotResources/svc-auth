package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

type sealedBearer struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

const sealKeyLen = chacha20poly1305.KeySize

func sealBearer(key []byte, token string, plaintext []byte) (sealedBearer, error) {
	if len(key) != sealKeyLen {
		return sealedBearer{}, errors.New("seal key must be 32 bytes")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return sealedBearer{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return sealedBearer{}, err
	}
	aad := []byte(bearerTokenHash(token))
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return sealedBearer{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func openBearer(key []byte, token string, sealed sealedBearer) ([]byte, error) {
	if len(key) != sealKeyLen {
		return nil, errors.New("seal key must be 32 bytes")
	}
	nonce, err := base64.StdEncoding.DecodeString(sealed.Nonce)
	if err != nil {
		return nil, errors.New("nonce is not base64")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return nil, errors.New("ciphertext is not base64")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("nonce length mismatch")
	}
	aad := []byte(bearerTokenHash(token))
	return aead.Open(nil, nonce, ciphertext, aad)
}
