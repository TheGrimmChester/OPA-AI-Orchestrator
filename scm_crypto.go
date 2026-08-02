package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const encryptedSecretPrefix = "enc:v1:"

// secretCryptoKey derives a 32-byte AES-256 key from OPA_CONNECTOR_SECRET
// (preferred) or a stable JWT_SECRET. Ephemeral JWT fallbacks are refused —
// ciphertext must survive Agent recreate.
func secretCryptoKey() ([]byte, error) {
	if s := strings.TrimSpace(os.Getenv("OPA_CONNECTOR_SECRET")); len(s) >= 16 {
		sum := sha256.Sum256([]byte(s))
		return sum[:], nil
	}
	if env := strings.TrimSpace(os.Getenv("JWT_SECRET")); len(env) >= 16 && env != jwtSecretPlaceholder {
		if len(env) < 32 {
			return nil, errors.New("JWT_SECRET too short for secret encryption (< 32 bytes); set OPA_CONNECTOR_SECRET or a >=32-byte JWT_SECRET")
		}
		sum := sha256.Sum256([]byte(env))
		return sum[:], nil
	}
	if jwtSecretEphemeral {
		return nil, errors.New("refuse ephemeral crypto key for secrets — set OPA_CONNECTOR_SECRET or a stable JWT_SECRET (>= 32 bytes)")
	}
	if len(jwtSecret) >= 16 {
		sum := sha256.Sum256(jwtSecret)
		return sum[:], nil
	}
	return nil, errors.New("no OPA_CONNECTOR_SECRET or JWT_SECRET for secret encryption")
}

func encryptSecret(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key, err := secretCryptoKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encryptedSecretPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func decryptSecret(ciphertext string) (string, error) {
	ciphertext = strings.TrimSpace(ciphertext)
	if ciphertext == "" {
		return "", nil
	}
	if !isEncryptedSecret(ciphertext) {
		return "", fmt.Errorf("not an encrypted secret")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(ciphertext, encryptedSecretPrefix))
	if err != nil {
		return "", err
	}
	key, err := secretCryptoKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	plain, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func isEncryptedSecret(ref string) bool {
	return strings.HasPrefix(strings.TrimSpace(ref), encryptedSecretPrefix)
}

// persistTokenRef returns AES-GCM ciphertext for ClickHouse token_ref.
// On crypto failure returns ("", err) — callers must NOT write empty token_ref
// over an existing ciphertext (would wipe the PAT).
func persistTokenRef(plaintext string) (string, error) {
	if strings.TrimSpace(plaintext) == "" {
		return "", nil
	}
	enc, err := encryptSecret(plaintext)
	if err != nil {
		return "", err
	}
	return enc, nil
}
