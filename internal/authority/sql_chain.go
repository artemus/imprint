package authority

import (
	"context"
	"database/sql"
)

type rowQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// LoadVerifiedChain reads the canonical ledger representation and verifies it
// before returning any derived authority state. Both *sql.DB and *sql.Tx satisfy
// rowQueryer, so callers can bind verification to an authority transaction.
func LoadVerifiedChain(ctx context.Context, queryer rowQueryer, expectedOperatorID, expectedStoreIdentity string) (VerifiedChain, error) {
	ledger, err := LoadLedgerRows(ctx, queryer)
	if err != nil {
		return VerifiedChain{}, err
	}
	return VerifyChain(ledger, expectedOperatorID, expectedStoreIdentity)
}

func LoadLedgerRows(ctx context.Context, queryer rowQueryer) ([]LedgerRow, error) {
	rows, err := queryer.QueryContext(ctx, `SELECT sequence,event_id,event_type,operator_id,install_id,key_id,event_json,event_sha256,signature_b64,previous_event_sha256,created_at FROM authority_ledger ORDER BY sequence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ledger := []LedgerRow{}
	for rows.Next() {
		var row LedgerRow
		var previous sql.NullString
		if err := rows.Scan(
			&row.Sequence, &row.EventID, &row.EventType, &row.OperatorID,
			&row.InstallID, &row.KeyID, &row.EventJSON, &row.EventSHA256,
			&row.SignatureB64, &previous, &row.CreatedAt,
		); err != nil {
			return nil, err
		}
		if previous.Valid {
			row.PreviousEventSHA256 = &previous.String
		}
		ledger = append(ledger, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ledger, nil
}
