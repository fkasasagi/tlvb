package tier2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// extractFirstJSONValue locates and returns the first balanced JSON object
// or array in `s`. Used to tolerate LLM output that wraps JSON in markdown
// fences, prose preambles, or appends trailing characters after a `}`/`]`.
//
// Strategy:
//   1. Strip optional markdown fences.
//   2. Find the first `{` or `[`.
//   3. Walk forward tracking brace depth, respecting string literals
//      (including escaped quotes) and matching the opening character.
//   4. Return the substring [start, end].
//
// Returns "" with an error if no balanced value is found.
func extractFirstJSONValue(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```JSON")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)

	objStart := strings.IndexAny(s, "{[")
	if objStart < 0 {
		return "", fmt.Errorf("no JSON value found")
	}
	open := s[objStart]
	close := byte('}')
	if open == '[' {
		close = ']'
	}

	depth := 0
	inStr := false
	escape := false
	for i := objStart; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if inStr {
			if c == '\\' {
				escape = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return s[objStart : i+1], nil
			}
		}
	}
	return "", fmt.Errorf("unbalanced JSON: depth=%d at EOF (raw head: %s)",
		depth, truncate(s, 200))
}

// decodeFirstJSON parses the first balanced JSON value into `dest` with
// LLM-output tolerance:
//   - markdown fences / prose preamble are stripped (extractFirstJSONValue)
//   - if body is array but dest is a struct → take first element
//   - if body is single object but dest is a slice → wrap as 1-element array
//   - if all of the above fail, return the underlying error verbatim
func decodeFirstJSON(s string, dest any) error {
	body, err := extractFirstJSONValue(s)
	if err != nil {
		return err
	}
	// Strict attempt first.
	dec := json.NewDecoder(bytes.NewReader([]byte(body)))
	if err := dec.Decode(dest); err == nil {
		return nil
	}

	trimmed := strings.TrimSpace(body)

	// Body is an array but dest expected a struct → first element.
	if strings.HasPrefix(trimmed, "[") {
		var arr []json.RawMessage
		if err := json.Unmarshal([]byte(body), &arr); err == nil && len(arr) > 0 {
			if err := json.Unmarshal(arr[0], dest); err == nil {
				return nil
			}
		}
	}

	// Body is a single object but dest expected a slice → wrap.
	if strings.HasPrefix(trimmed, "{") {
		wrapped := "[" + body + "]"
		if err := json.Unmarshal([]byte(wrapped), dest); err == nil {
			return nil
		}
	}

	// All recovery paths failed — return the strict error so callers
	// get an actionable message.
	return json.Unmarshal([]byte(body), dest)
}
