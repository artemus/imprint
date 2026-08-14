package authority

import "errors"

type rebindDetails struct {
	KeyID                string                    `json:"key_id"`
	PublicKeyB64         string                    `json:"public_key_b64"`
	PublicKeyFingerprint string                    `json:"public_key_fingerprint"`
	InstallID            string                    `json:"install_id"`
	BlobRelativePath     string                    `json:"blob_rel_path"`
	BlobSHA256           string                    `json:"blob_sha256"`
	BlobSize             int64                     `json:"blob_size"`
	AlgorithmSuite       string                    `json:"algorithm_suite"`
	OldInstallID         string                    `json:"old_install_id"`
	Authorization        installationAuthorization `json:"authorization"`
}

var rebindDetailFields = []string{"key_id", "public_key_b64", "public_key_fingerprint", "install_id", "blob_rel_path", "blob_sha256", "blob_size", "algorithm_suite", "old_install_id", "authorization"}

// VerifyInstallationRebound verifies replacement of one installation identity
// by another without mutating the previously verified chain state.
func VerifyInstallationRebound(prior ChainState, row LedgerRow) (ChainState, error) {
	event, digest, _, err := verifyLifecycle(prior, row, "installation_rebound")
	if err != nil {
		return ChainState{}, err
	}
	var details rebindDetails
	if decodeExactObject(event.Details, &details, rebindDetailFields) != nil {
		return ChainState{}, errors.New("authority rebind has unknown or missing fields")
	}
	var oldKey ChainKey
	activeOld := 0
	for _, key := range prior.Keys {
		if key.InstallID == details.OldInstallID && key.Status == "active" {
			oldKey, activeOld = key, activeOld+1
		}
	}
	if activeOld != 1 {
		return ChainState{}, errors.New("authority rebind source installation is ambiguous")
	}
	certificate := KeyCertificate{KeyID: details.KeyID, PublicKeyB64: details.PublicKeyB64, PublicKeyFingerprint: details.PublicKeyFingerprint, InstallID: details.InstallID}
	if err := validateCertificate(certificate); err != nil {
		return ChainState{}, err
	}
	if event.KeyID != certificate.KeyID || event.InstallID != certificate.InstallID {
		return ChainState{}, errors.New("authority rebind certificate subject mismatch")
	}
	if _, exists := prior.Keys[certificate.KeyID]; exists {
		return ChainState{}, errors.New("authority rebind key already exists")
	}
	for _, key := range prior.Keys {
		if key.Kind == "installation" && key.InstallID == certificate.InstallID && key.Status == "active" {
			return ChainState{}, errors.New("authority rebind target installation is already active")
		}
	}
	if validateInstallationBlob(details.AlgorithmSuite, details.BlobRelativePath, details.BlobSHA256, details.BlobSize) != nil {
		return ChainState{}, errors.New("authority rebind blob binding is invalid")
	}
	authorizationRaw, err := rawObjectField(event.Details, "authorization")
	if err != nil || validateInstallationAuthorization(prior, certificate, authorizationRaw, &details.Authorization) != nil {
		return ChainState{}, errors.New("installation rebind authorization is invalid")
	}
	next := ChainState{OperatorID: prior.OperatorID, StoreIdentity: prior.StoreIdentity, HeadSHA256: digest, HeadSequence: event.Sequence, Keys: cloneKeys(prior.Keys)}
	retired := next.Keys[oldKey.KeyID]
	retired.Status, retired.EffectiveAt = "retired", event.CreatedAt
	next.Keys[oldKey.KeyID] = retired
	next.Keys[certificate.KeyID] = ChainKey{
		KeyCertificate: certificate, Kind: "installation", Status: "active", Paired: true,
		AlgorithmSuite: details.AlgorithmSuite, BlobRelativePath: details.BlobRelativePath,
		BlobSHA256: details.BlobSHA256, BlobSize: details.BlobSize,
		CertificateSequence: event.Sequence, CertificateEventSHA256: digest,
		EffectiveAt: event.CreatedAt,
	}
	return next, nil
}
