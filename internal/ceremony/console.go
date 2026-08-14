// Package ceremony provides the native terminal boundary for authority actions.
package ceremony

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type Console interface {
	RequireNative(io.Reader) error
	Write(string) error
	ReadLine(string) (string, error)
	ReadSecret(string) (string, error)
}

type NativeConsole struct{}

func (NativeConsole) RequireNative(processInput io.Reader) error {
	if os.Getenv("IMPRINT_HOOK") == "1" || os.Getenv("IMPRINT_NONINTERACTIVE") == "1" {
		return errors.New("hooks and non-interactive processes cannot raise authority")
	}
	input, ok := processInput.(*os.File)
	if !ok || !term.IsTerminal(int(input.Fd())) {
		return errors.New("redirected stdin cannot raise authority")
	}
	reader, writer, err := openNativeConsole()
	if err != nil {
		return errors.New("native TTY/console is required for authority operations")
	}
	defer reader.Close()
	defer writer.Close()
	if !term.IsTerminal(int(reader.Fd())) || !term.IsTerminal(int(writer.Fd())) {
		return errors.New("native TTY/console is required for authority operations")
	}
	return nil
}

func (NativeConsole) Write(value string) error {
	reader, writer, err := checkedNativeConsole()
	if err != nil {
		return err
	}
	defer reader.Close()
	defer writer.Close()
	_, err = io.WriteString(writer, value)
	return err
}

func (NativeConsole) ReadLine(prompt string) (string, error) {
	reader, writer, err := checkedNativeConsole()
	if err != nil {
		return "", err
	}
	defer reader.Close()
	defer writer.Close()
	if _, err := io.WriteString(writer, prompt); err != nil {
		return "", err
	}
	value, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil {
		return "", errors.New("native TTY input ended unexpectedly")
	}
	return strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r"), nil
}

func (NativeConsole) ReadSecret(prompt string) (string, error) {
	reader, writer, err := checkedNativeConsole()
	if err != nil {
		return "", err
	}
	defer reader.Close()
	defer writer.Close()
	if _, err := io.WriteString(writer, prompt); err != nil {
		return "", err
	}
	secret, err := term.ReadPassword(int(reader.Fd()))
	_, newlineErr := io.WriteString(writer, "\n")
	if err != nil {
		clear(secret)
		return "", errors.New("authority secret entry was cancelled")
	}
	if newlineErr != nil {
		clear(secret)
		return "", newlineErr
	}
	value := string(secret)
	clear(secret)
	return value, nil
}

func checkedNativeConsole() (*os.File, *os.File, error) {
	reader, writer, err := openNativeConsole()
	if err != nil {
		return nil, nil, errors.New("native TTY/console is required for authority operations")
	}
	if !term.IsTerminal(int(reader.Fd())) || !term.IsTerminal(int(writer.Fd())) {
		reader.Close()
		writer.Close()
		return nil, nil, errors.New("native TTY/console is required for authority operations")
	}
	return reader, writer, nil
}
