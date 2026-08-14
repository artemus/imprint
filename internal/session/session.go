// Package session maps provider session identifiers to opaque local URNs.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/artemus/imprint/internal/privateio"
)

func OpaqueURN(root, native string) (string, error) {
	key, err := loadOrCreateKey(root)
	if err != nil {
		return "", err
	}
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write([]byte(native))
	raw := digest.Sum(nil)[:16]
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw)
	uuid := encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
	return "urn:imprint:session:" + uuid, nil
}
func loadOrCreateKey(root string) ([]byte, error) {
	path := filepath.Join(root, "session-map.key")
	for attempts := 0; attempts < 2; attempts++ {
		raw, err := os.ReadFile(path)
		if err == nil {
			key, decodeErr := hex.DecodeString(string(bytesTrimSpace(raw)))
			if decodeErr != nil || len(key) != 32 {
				return nil, errors.New("session mapping key is corrupt")
			}
			return key, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		encoded := append([]byte(hex.EncodeToString(key)), '\n')
		if err = privateio.PublishNew(path, encoded); err == nil {
			return key, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("session key publication raced repeatedly")
}
func bytesTrimSpace(value []byte) []byte {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\n' || value[start] == '\r' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\n' || value[end-1] == '\r' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}
