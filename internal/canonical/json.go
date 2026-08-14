// Package canonical provides the stable JSON encoding used by Imprint 3.1.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// JSON matches Python's sorted, compact, UTF-8 json.dumps contract. It is not
// RFC 8785: compatibility with existing store and spool hashes takes priority.
func JSON(value any) ([]byte, error) {
	intermediate, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(intermediate))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected trailing JSON")
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}
