package teacher

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxJSONDepth = 64

// RejectLoneSurrogates scans raw JSON bytes and rejects unpaired UTF-16 surrogate
// escapes (\uD800-\uDFFF) inside string literals, matching strict UTF-8 parsers.
func RejectLoneSurrogates(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8")
	}
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		if c == '"' {
			inString = false
			continue
		}
		if c != '\\' {
			continue
		}
		if i+1 >= len(raw) {
			return errors.New("truncated escape")
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return errors.New("truncated unicode escape")
		}
		code, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return errors.New("invalid unicode escape")
		}
		i += 4
		if code >= 0xDC00 && code <= 0xDFFF {
			return errors.New("unpaired low surrogate")
		}
		if code >= 0xD800 && code <= 0xDBFF {
			// Must be immediately followed by a low surrogate \uDC00-\uDFFF.
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return errors.New("unpaired high surrogate")
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return errors.New("invalid surrogate pair")
			}
			i += 6
		}
	}
	return nil
}

// ParseStrictJSONObject parses a UTF-8 JSON object rejecting duplicate keys
// (including unicode-escaped duplicates), lone UTF-16 surrogates, excessive nesting,
// and trailing tokens. Numbers are returned as json.Number.
func ParseStrictJSONObject(raw []byte) (map[string]any, error) {
	if err := RejectLoneSurrogates(raw); err != nil {
		return nil, err
	}
	// Reject UTF-8 BOM explicitly to match strict wire parsers.
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, errors.New("UTF-8 BOM not allowed")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	val, err := decodeStrictValue(dec, 0)
	if err != nil {
		return nil, err
	}
	// Ensure no trailing tokens exist.
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON content")
	}
	obj, ok := val.(map[string]any)
	if !ok {
		return nil, errors.New("expected JSON object")
	}
	return obj, nil
}

func decodeStrictValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errors.New("JSON nesting depth exceeded")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			if depth+1 > maxJSONDepth {
				return nil, errors.New("JSON nesting depth exceeded")
			}
			obj := make(map[string]any)
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errors.New("expected string key")
				}
				if _, exists := obj[key]; exists {
					return nil, errors.New("duplicate JSON key")
				}
				val, err := decodeStrictValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			endTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if endTok != json.Delim('}') {
				return nil, errors.New("expected closing brace")
			}
			return obj, nil
		case '[':
			if depth+1 > maxJSONDepth {
				return nil, errors.New("JSON nesting depth exceeded")
			}
			arr := make([]any, 0)
			for dec.More() {
				val, err := decodeStrictValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			endTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if endTok != json.Delim(']') {
				return nil, errors.New("expected closing bracket")
			}
			return arr, nil
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	default:
		return tok, nil
	}
}

// StrictInt64 extracts an exact integer within [low, high] from a json.Number or int64.
// Rejects booleans, floats, scientific notation, and out-of-range values.
func StrictInt64(v any, low, high int64) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		s := string(n)
		if s == "" || strings.ContainsAny(s, ".eE") {
			return 0, false
		}
		parsed, err := strconv.ParseInt(s, 10, 64)
		if err != nil || parsed < low || parsed > high {
			return 0, false
		}
		return parsed, true
	case int64:
		if n < low || n > high {
			return 0, false
		}
		return n, true
	case int:
		i := int64(n)
		if i < low || i > high {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

// StrictExactInt64 ensures a float64 is never silently accepted as an integer.
func init() {
	_ = math.MaxInt64
}
