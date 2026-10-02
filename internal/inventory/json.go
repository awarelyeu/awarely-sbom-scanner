package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// ValidateJSON bounds recursive input and rejects duplicate object members,
// including equivalent escaped names. Unknown project fields are validated
// but never copied to the inventory.
func ValidateJSON(ctx context.Context, b []byte) error {
	if len(b) > MaxManifestBytes || !utf8.Valid(b) {
		return errors.New("invalid or oversized JSON")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	nodes := 0
	var value func(int) error
	value = func(depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		nodes++
		if depth > 16 || nodes > 150000 {
			return errors.New("JSON complexity limit exceeded")
		}
		t, err := d.Token()
		if err != nil {
			return errors.New("invalid JSON")
		}
		if s, ok := t.(string); ok && len(s) > 16384 {
			return errors.New("JSON string limit exceeded")
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return errors.New("invalid JSON object")
					}
					s, ok := key.(string)
					if !ok || len(s) > 1024 || seen[s] {
						return errors.New("duplicate or invalid JSON member")
					}
					seen[s] = true
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return errors.New("invalid JSON object")
				}
			case '[':
				for d.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return errors.New("invalid JSON array")
				}
			default:
				return errors.New("invalid JSON delimiter")
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
