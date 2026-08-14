// Package paths resolves private state without accepting dangerous roots.
package paths

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/artemus/imprint/internal/config"
)

var syncMarkers = []string{"dropbox", "onedrive", "cloudstorage", "google drive"}

func OperatorRoot(value config.Config) (string, error) {
	base := value.DataRoot
	if base == "" {
		if override := os.Getenv("IMPRINT_DATA_ROOT"); override != "" {
			base = override
		} else if runtime.GOOS == "windows" {
			base = os.Getenv("LOCALAPPDATA")
			if base == "" {
				return "", errors.New("LOCALAPPDATA is required on Windows")
			}
			base = filepath.Join(base, "Imprint")
		} else {
			base = os.Getenv("XDG_DATA_HOME")
			if base == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return "", err
				}
				base = filepath.Join(home, ".local", "share")
			}
			base = filepath.Join(base, "imprint")
		}
	}
	if !filepath.IsAbs(base) {
		return "", errors.New("Imprint data root must be absolute")
	}
	clean := filepath.Clean(base)
	home, _ := os.UserHomeDir()
	if clean == filepath.VolumeName(clean)+string(filepath.Separator) || (home != "" && clean == filepath.Clean(home)) {
		return "", errors.New("refusing root or home as Imprint data root")
	}
	lower := strings.ToLower(clean)
	for _, marker := range syncMarkers {
		if strings.Contains(lower, marker) {
			return "", errors.New("cloud-sync roots are unsupported for the canonical database")
		}
	}
	return filepath.Join(clean, value.OperatorSlug), nil
}
