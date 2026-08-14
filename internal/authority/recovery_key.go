package authority

import "errors"

var recoveryCertificateFields = []string{"key_id", "public_key_b64", "public_key_fingerprint", "install_id"}

// VerifyRecoveryCreated verifies certification of a new recovery key. Bundle
// encryption and persistence remain separate from ledger-chain verification.
func VerifyRecoveryCreated(prior ChainState, row LedgerRow) (ChainState, error) {
	event, digest, _, err := verifyLifecycle(prior, row, "recovery_created")
	if err != nil {
		return ChainState{}, err
	}
	var certificate KeyCertificate
	if decodeExactObject(event.Details, &certificate, recoveryCertificateFields) != nil {
		return ChainState{}, errors.New("authority recovery certificate has unknown or missing fields")
	}
	if event.KeyID != certificate.KeyID || event.InstallID != certificate.InstallID {
		return ChainState{}, errors.New("authority recovery certificate subject mismatch")
	}
	if err := validateCertificate(certificate); err != nil {
		return ChainState{}, err
	}
	if _, exists := prior.Keys[certificate.KeyID]; exists {
		return ChainState{}, errors.New("authority key identity was certified twice")
	}
	next := ChainState{OperatorID: prior.OperatorID, StoreIdentity: prior.StoreIdentity, HeadSHA256: digest, HeadSequence: event.Sequence, Keys: cloneKeys(prior.Keys)}
	next.Keys[certificate.KeyID] = ChainKey{
		KeyCertificate: certificate, Kind: "recovery", Status: "active",
		CertificateSequence: event.Sequence, CertificateEventSHA256: digest,
		EffectiveAt: event.CreatedAt,
	}
	return next, nil
}
