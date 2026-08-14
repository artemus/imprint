package authority

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

type EnrollmentPlan struct {
	Event      GenesisEvent
	PrivateKey ed25519.PrivateKey
	KeyBlob    []byte
}

type EnrollmentIdentity struct {
	OperatorID, StoreIdentity, InstallID string
}

// Clear releases the prepared private-key bytes as soon as the enrollment
// transaction no longer needs them.
func (plan *EnrollmentPlan) Clear() {
	clear(plan.PrivateKey)
	plan.PrivateKey = nil
}

func NewEnrollmentIdentity(operatorID, storeIdentity string, random io.Reader) (EnrollmentIdentity, error) {
	if !strings.HasPrefix(operatorID, "urn:imprint:operator:") {
		return EnrollmentIdentity{}, errors.New("configured operator identity is invalid")
	}
	if !strings.HasPrefix(storeIdentity, "urn:imprint:store:") {
		return EnrollmentIdentity{}, errors.New("store identity is corrupt")
	}
	if random == nil {
		random = rand.Reader
	}
	installationRandom := make([]byte, 32)
	if _, err := io.ReadFull(random, installationRandom); err != nil {
		return EnrollmentIdentity{}, errors.New("authority enrollment randomness failed")
	}
	return EnrollmentIdentity{
		OperatorID: operatorID, StoreIdentity: storeIdentity,
		InstallID: "urn:imprint:installation:" + hex.EncodeToString(installationRandom),
	}, nil
}

// PrepareEnrollmentWithoutRecovery builds the exact first-trust material used
// after the operator explicitly declines an offline recovery key.
func PrepareEnrollmentWithoutRecovery(operatorID, storeIdentity, passphrase string, now time.Time, random io.Reader) (EnrollmentPlan, error) {
	if random == nil {
		random = rand.Reader
	}
	identity, err := NewEnrollmentIdentity(operatorID, storeIdentity, random)
	if err != nil {
		return EnrollmentPlan{}, err
	}
	return PrepareEnrollmentForIdentity(identity, passphrase, now, random)
}

func PrepareEnrollmentForIdentity(identity EnrollmentIdentity, passphrase string, now time.Time, random io.Reader) (EnrollmentPlan, error) {
	installationSuffix := strings.TrimPrefix(identity.InstallID, "urn:imprint:installation:")
	if !strings.HasPrefix(identity.OperatorID, "urn:imprint:operator:") || !strings.HasPrefix(identity.StoreIdentity, "urn:imprint:store:") ||
		!strings.HasPrefix(identity.InstallID, "urn:imprint:installation:") || !lowercaseSHA256.MatchString(installationSuffix) {
		return EnrollmentPlan{}, errors.New("authority enrollment identity is invalid")
	}
	if random == nil {
		random = rand.Reader
	}
	key, err := GenerateKey(random)
	if err != nil {
		return EnrollmentPlan{}, err
	}
	nonceRandom := make([]byte, 32)
	if _, err := io.ReadFull(random, nonceRandom); err != nil {
		clear(key.PrivateKey)
		return EnrollmentPlan{}, errors.New("authority enrollment randomness failed")
	}
	eventUUID, err := uuid.NewRandomFromReader(random)
	if err != nil {
		clear(key.PrivateKey)
		return EnrollmentPlan{}, errors.New("authority enrollment randomness failed")
	}
	createdAt := utcText(now)
	publicKeyB64 := base64.StdEncoding.EncodeToString(key.PublicKey)
	event := GenesisEvent{
		ContractVersion: GenesisEventVersion, DomainSeparator: LedgerDomain,
		Sequence: 1, EventID: "urn:imprint:authority-event:" + eventUUID.String(),
		EventType: "enrollment", OperatorID: identity.OperatorID, InstallID: identity.InstallID,
		StoreIdentity: identity.StoreIdentity, KeyID: key.KeyID, PublicKeyB64: publicKeyB64,
		PublicKeyFingerprint: key.Fingerprint, AlgorithmSuite: AlgorithmSuite,
		EnrollmentNonce: base64.RawURLEncoding.EncodeToString(nonceRandom), Status: "active",
		CreatedAt: createdAt, BlobRelativePath: "authority/keys/" + strings.TrimPrefix(key.Fingerprint, "sha256:") + ".blob",
	}
	blob, err := EncryptPrivateKey(key.PrivateKey, passphrase, KeyAAD{
		OperatorID: identity.OperatorID, InstallID: identity.InstallID, StoreIdentity: identity.StoreIdentity,
		KeyID: key.KeyID, PublicKeyB64: publicKeyB64, PublicKeyFingerprint: key.Fingerprint,
		CreatedAt: createdAt, AlgorithmSuite: AlgorithmSuite, LedgerSequence: 1,
		EnrollmentNonce: event.EnrollmentNonce,
	}, random)
	if err != nil {
		clear(key.PrivateKey)
		return EnrollmentPlan{}, err
	}
	digest := sha256.Sum256(blob)
	event.BlobSHA256, event.BlobSize = hex.EncodeToString(digest[:]), int64(len(blob))
	return EnrollmentPlan{Event: event, PrivateKey: key.PrivateKey, KeyBlob: blob}, nil
}
