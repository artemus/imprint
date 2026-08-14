//go:build windows

package ceremony

import "os"

func openNativeConsole() (*os.File, *os.File, error) {
	reader, err := os.OpenFile("CONIN$", os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, err
	}
	writer, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		reader.Close()
		return nil, nil, err
	}
	return reader, writer, nil
}
