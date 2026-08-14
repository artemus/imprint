package authority

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

const KeyStateVersion = "imprint.authority.key-state/1.0.0"

type keyStateDocument struct {
	Version string          `json:"key_state_version"`
	Keys    []keyStateEntry `json:"keys"`
}

type keyStateEntry struct {
	KeyID                  string  `json:"key_id"`
	PublicKeyB64           string  `json:"public_key_b64"`
	PublicKeyFingerprint   string  `json:"public_key_fingerprint"`
	InstallID              string  `json:"install_id"`
	Kind                   string  `json:"kind"`
	Status                 string  `json:"status"`
	Paired                 bool    `json:"paired"`
	CertificateSequence    int64   `json:"certificate_sequence"`
	CertificateEventSHA256 string  `json:"certificate_event_sha256"`
	EffectiveAt            string  `json:"effective_at"`
	CompromisedAt          *string `json:"compromised_at"`
	ReplacementKeyID       *string `json:"replacement_key_id"`
}

// KeyStateSHA256 returns the canonical digest bound into authority checkpoints.
func KeyStateSHA256(keys map[string]ChainKey) (string, error) {
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	document := keyStateDocument{Version: KeyStateVersion, Keys: make([]keyStateEntry, 0, len(ids))}
	for _, id := range ids {
		key := keys[id]
		document.Keys = append(document.Keys, keyStateEntry{
			KeyID: key.KeyID, PublicKeyB64: key.PublicKeyB64,
			PublicKeyFingerprint: key.PublicKeyFingerprint, InstallID: key.InstallID,
			Kind: key.Kind, Status: key.Status, Paired: key.Paired,
			CertificateSequence:    key.CertificateSequence,
			CertificateEventSHA256: key.CertificateEventSHA256,
			EffectiveAt:            key.EffectiveAt, CompromisedAt: key.CompromisedAt,
			ReplacementKeyID: key.ReplacementKeyID,
		})
	}
	encoded, err := canonicalContract(document)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
