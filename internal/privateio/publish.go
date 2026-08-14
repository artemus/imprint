// Package privateio durably publishes private create-only files.
package privateio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func EnsureDir(path string) error {
	if err := rejectSymlinkAncestors(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("private path is not a real directory")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func PublishNew(path string, content []byte) error {
	parent := filepath.Dir(path)
	if err := EnsureDir(parent); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(parent, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if runtime.GOOS != "windows" {
		if err := temporary.Chmod(0o600); err != nil {
			temporary.Close()
			return err
		}
	}
	if _, err = temporary.Write(content); err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return os.ErrExist
		}
		return fmt.Errorf("publish private file: %w", err)
	}
	if err = os.Remove(temporaryPath); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err = os.Chmod(path, 0o600); err != nil {
			return err
		}
		directory, openErr := os.Open(parent)
		if openErr == nil {
			err = directory.Sync()
			_ = directory.Close()
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func rejectSymlinkAncestors(path string) error {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	current := string(filepath.Separator)
	if volume != "" {
		current = volume + string(filepath.Separator)
	}
	relative := stringsTrimVolumeRoot(clean, volume)
	for _, part := range splitPath(relative) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("private path contains symlink: %s", current)
		}
	}
	return nil
}

func stringsTrimVolumeRoot(path, volume string) string {
	value := path
	if volume != "" {
		value = value[len(volume):]
	}
	for len(value) > 0 && os.IsPathSeparator(value[0]) {
		value = value[1:]
	}
	return value
}
func splitPath(path string) []string {
	result := []string{}
	for path != "" && path != "." {
		dir, file := filepath.Split(path)
		if file != "" {
			result = append([]string{file}, result...)
		}
		next := filepath.Clean(dir)
		if next == path {
			break
		}
		path = next
	}
	return result
}
