// Package urn implements Imprint's canonical typed UUIDv4 identifiers.
package urn

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

func New(kind string) (string, error) {
	if !kindPattern.MatchString(kind) {
		return "", fmt.Errorf("invalid URN kind: %s", kind)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	uuid := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
	return "urn:imprint:" + kind + ":" + uuid, nil
}

func Require(value, kind string) error {
	parts := strings.Split(value, ":")
	if len(parts) != 4 || parts[0] != "urn" || parts[1] != "imprint" {
		return errors.New("must be an Imprint URN")
	}
	if !kindPattern.MatchString(parts[2]) || (kind != "" && parts[2] != kind) {
		return fmt.Errorf("must be a %s URN", kind)
	}
	uuid := parts[3]
	if len(uuid) != 36 || uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' || uuid[14] != '4' {
		return errors.New("must contain canonical UUIDv4")
	}
	for index, char := range uuid {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", char) {
			return errors.New("must contain canonical UUIDv4")
		}
	}
	if !strings.ContainsRune("89ab", rune(uuid[19])) {
		return errors.New("must contain canonical UUIDv4")
	}
	return nil
}
