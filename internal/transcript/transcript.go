// Package transcript reads a bounded, descriptor-bound Claude Code transcript.
package transcript

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const MaxBytes int64 = 16 * 1024 * 1024
const tailBytes int64 = 2 * 1024 * 1024

type Result struct {
	OperatorText    string
	PriorAssistant  string
	CaseDescription string
	SourceLocator   string
	Degradation     map[string]any
}
type snapshot struct {
	data         []byte
	size, offset int64
}

func Parse(path string) (Result, error) {
	view, err := readSnapshot(path)
	if err != nil {
		return Result{}, err
	}
	return parse(view)
}

func readSnapshot(path string) (snapshot, error) {
	if !filepath.IsAbs(path) {
		return snapshot{}, errors.New("transcript_path must be an absolute regular non-symlink file")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return snapshot{}, errors.New("transcript_path must be an absolute regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return snapshot{}, errors.New("transcript_path must be an absolute regular non-symlink file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return snapshot{}, errors.New("transcript_path changed while it was being opened")
	}
	size := opened.Size()
	if size <= 0 {
		return snapshot{}, errors.New("transcript_path size is outside the supported bound")
	}
	readSize := size
	if readSize > MaxBytes {
		readSize = tailBytes
		if size < readSize {
			readSize = size
		}
	}
	offset := size - readSize
	data := make([]byte, readSize)
	read, err := file.ReadAt(data, offset)
	if err != nil && err != io.EOF {
		return snapshot{}, err
	}
	if int64(read) != readSize {
		return snapshot{}, errors.New("transcript_path changed during the bounded read")
	}
	after, err := file.Stat()
	if err != nil {
		return snapshot{}, err
	}
	pathAfter, err := os.Lstat(path)
	if err != nil || !pathAfter.Mode().IsRegular() || !os.SameFile(opened, pathAfter) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return snapshot{}, errors.New("transcript_path changed during the bounded read")
	}
	return snapshot{data, size, offset}, nil
}

func parse(view snapshot) (Result, error) {
	data := view.data
	if view.offset > 0 {
		if index := bytes.IndexByte(data, '\n'); index >= 0 {
			data = data[index+1:]
		} else {
			data = nil
		}
	}
	if !json.Valid([]byte(`"`+strings.ReplaceAll(string(data), `"`, `\"`)+`"`)) && !bytes.Equal(bytes.ToValidUTF8(data, nil), data) {
		return Result{}, errors.New("transcript is not valid UTF-8")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	messages := []message{}
	skipped := []int{}
	line := 0
	for scanner.Scan() {
		line++
		raw := append([]byte(nil), scanner.Bytes()...)
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var item struct {
			Type    string `json:"type"`
			Message struct {
				Content any `json:"content"`
			} `json:"message"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			skipped = append(skipped, line)
			continue
		}
		if item.Type != "user" && item.Type != "assistant" {
			continue
		}
		text := messageText(item.Message.Content)
		if strings.TrimSpace(text) != "" {
			messages = append(messages, message{item.Type, text})
		}
	}
	if err := scanner.Err(); err != nil {
		return Result{}, err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' && data[len(data)-1] != '\r' {
		last := bytes.TrimSpace(data[bytes.LastIndexByte(data, '\n')+1:])
		if len(last) > 0 && !json.Valid(last) {
			return Result{}, fmt.Errorf("incomplete transcript line %d", line+boolInt(line == 0))
		}
	}
	userIndex := -1
	for index := range messages {
		if messages[index].kind == "user" {
			userIndex = index
		}
	}
	if userIndex < 0 {
		return Result{}, errors.New("transcript contains no user message")
	}
	prior := ""
	for index := userIndex - 1; index >= 0; index-- {
		if messages[index].kind == "assistant" {
			prior = messages[index].text
			break
		}
	}
	hash := sha256.Sum256(data)
	result := Result{OperatorText: messages[userIndex].text, PriorAssistant: prior, CaseDescription: "Explicit operator feedback witnessed in the Claude Code transcript", SourceLocator: "transcript:sha256:" + hex.EncodeToString(hash[:])}
	if view.offset > 0 {
		result.CaseDescription = "Explicit operator feedback witnessed in a bounded Claude Code transcript tail"
		if len([]byte(prior)) > 64*1024 {
			prior = truncateUTF8(prior, 64*1024)
			result.PriorAssistant = prior
		}
		result.SourceLocator = "transcript-tail:sha256:" + hex.EncodeToString(hash[:])
		result.Degradation = map[string]any{"transcript_bytes": view.size, "tail_bytes_examined": len(data), "evidence_sha256": hex.EncodeToString(hash[:]), "hash_scope": "bounded_tail", "truncated": true, "context_truncated": view.offset > 0, "receipt": "huge_transcript_bounded_tail", "skipped_malformed_line_count": len(skipped), "skipped_malformed_lines": skipped}
	} else if len(skipped) > 0 {
		result.Degradation = map[string]any{"receipt": "historic_malformed_lines_skipped", "truncated": false, "skipped_malformed_line_count": len(skipped), "skipped_malformed_lines": skipped}
	}
	return result, nil
}

type message struct{ kind, text string }

func messageText(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	items, ok := value.([]any)
	if !ok {
		return ""
	}
	parts := []string{}
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok || item["type"] != "text" {
			continue
		}
		if text, ok := item["text"].(string); ok {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "\n")
}
func truncateUTF8(value string, limit int) string {
	raw := []byte(value)
	if len(raw) <= limit {
		return value
	}
	raw = raw[:limit]
	for !bytes.Equal(bytes.ToValidUTF8(raw, nil), raw) && len(raw) > 0 {
		raw = raw[:len(raw)-1]
	}
	return string(raw)
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
