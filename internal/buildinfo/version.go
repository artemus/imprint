// Package buildinfo owns version metadata for every Imprint binary.
package buildinfo

// These values are overridden by release builds with -ldflags. Keeping the
// defaults useful makes local builds deterministic and easy to identify.
var (
	Version = "3.2.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)
