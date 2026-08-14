package authority

import "errors"

const InstallationAuthorizationVersion = "imprint.authority.authorize-installation/1.0.0"

type installationAuthorization struct {
	CertificateVersion           string `json:"certificate_version"`
	OperatorID                   string `json:"operator_id"`
	StoreIdentity                string `json:"store_identity"`
	NewInstallID                 string `json:"new_install_id"`
	NewKeyID                     string `json:"new_key_id"`
	NewPublicKeyB64              string `json:"new_public_key_b64"`
	PairingNonce                 string `json:"pairing_nonce"`
	PairingRequestSHA256         string `json:"pairing_request_sha256"`
	PrecedingAuthorityHeadSHA256 string `json:"preceding_authority_head_sha256"`
	ExpiresAt                    string `json:"expires_at"`
}

type pairingDetails struct {
	KeyID                string                    `json:"key_id"`
	PublicKeyB64         string                    `json:"public_key_b64"`
	PublicKeyFingerprint string                    `json:"public_key_fingerprint"`
	InstallID            string                    `json:"install_id"`
	BlobRelativePath     string                    `json:"blob_rel_path"`
	BlobSHA256           string                    `json:"blob_sha256"`
	BlobSize             int64                     `json:"blob_size"`
	AlgorithmSuite       string                    `json:"algorithm_suite"`
	Authorization        installationAuthorization `json:"authorization"`
}

var pairingDetailFields = []string{"key_id", "public_key_b64", "public_key_fingerprint", "install_id", "blob_rel_path", "blob_sha256", "blob_size", "algorithm_suite", "authorization"}
var installationAuthorizationFields = []string{"certificate_version", "operator_id", "store_identity", "new_install_id", "new_key_id", "new_public_key_b64", "pairing_nonce", "pairing_request_sha256", "preceding_authority_head_sha256", "expires_at"}

// VerifyInstallationPaired verifies a signed installation certificate and its
// authorization binding against an already verified authority chain.
func VerifyInstallationPaired(prior ChainState, row LedgerRow) (ChainState, error) {
	event, digest, _, err := verifyLifecycle(prior, row, "installation_paired")
	if err != nil {
		return ChainState{}, err
	}
	var details pairingDetails
	if decodeExactObject(event.Details, &details, pairingDetailFields) != nil {
		return ChainState{}, errors.New("authority installation certificate has unknown or missing fields")
	}
	certificate := KeyCertificate{KeyID: details.KeyID, PublicKeyB64: details.PublicKeyB64, PublicKeyFingerprint: details.PublicKeyFingerprint, InstallID: details.InstallID}
	if err := validateCertificate(certificate); err != nil {
		return ChainState{}, err
	}
	if event.KeyID != certificate.KeyID || event.InstallID != certificate.InstallID {
		return ChainState{}, errors.New("authority installation certificate subject mismatch")
	}
	if _, exists := prior.Keys[certificate.KeyID]; exists {
		return ChainState{}, errors.New("authority key identity was certified twice")
	}
	for _, key := range prior.Keys {
		if key.Kind == "installation" && key.InstallID == certificate.InstallID && key.Status == "active" {
			return ChainState{}, errors.New("authority installation already has an active key")
		}
	}
	if validateInstallationBlob(details.AlgorithmSuite, details.BlobRelativePath, details.BlobSHA256, details.BlobSize) != nil {
		return ChainState{}, errors.New("authority installation blob binding is invalid")
	}
	authorizationRaw, err := rawObjectField(event.Details, "authorization")
	if err != nil || validateInstallationAuthorization(prior, certificate, authorizationRaw, &details.Authorization) != nil {
		return ChainState{}, errors.New("installation authorization certificate is invalid")
	}
	next := ChainState{OperatorID: prior.OperatorID, StoreIdentity: prior.StoreIdentity, HeadSHA256: digest, HeadSequence: event.Sequence, Keys: cloneKeys(prior.Keys)}
	next.Keys[certificate.KeyID] = ChainKey{
		KeyCertificate: certificate, Kind: "installation", Status: "active", Paired: true,
		AlgorithmSuite: details.AlgorithmSuite, BlobRelativePath: details.BlobRelativePath,
		BlobSHA256: details.BlobSHA256, BlobSize: details.BlobSize,
		CertificateSequence: event.Sequence, CertificateEventSHA256: digest,
		EffectiveAt: event.CreatedAt,
	}
	return next, nil
}

func validateInstallationAuthorization(prior ChainState, certificate KeyCertificate, raw []byte, authorization *installationAuthorization) error {
	if decodeExactObject(raw, authorization, installationAuthorizationFields) != nil || authorization.CertificateVersion != InstallationAuthorizationVersion || authorization.OperatorID != prior.OperatorID || authorization.StoreIdentity != prior.StoreIdentity || authorization.NewInstallID != certificate.InstallID || authorization.NewKeyID != certificate.KeyID || authorization.NewPublicKeyB64 != certificate.PublicKeyB64 || authorization.PrecedingAuthorityHeadSHA256 != prior.HeadSHA256 {
		return errors.New("installation authorization certificate is invalid")
	}
	_, err := utcTimestamp(authorization.ExpiresAt)
	return err
}
