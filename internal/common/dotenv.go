package common

import (
	"bufio"
	"os"
	"strings"
)

// LoadDotEnv reads simple KEY=VALUE lines from path and sets each key
// in the process env via os.Setenv — but only when the key is not
// already set, so the shell-supplied env still wins.
//
// Format (intentionally minimal — no exports, no shell expansion):
//
//	# comment lines are ignored
//	ANTHROPIC_API_KEY=sk-ant-...
//	FOO=bar baz                  # everything after = is the value
//	QUOTED="leading + trailing quotes are stripped"
//
// Missing file → no error (this is opt-in, not required).
//
// Loading order in cmd/tlvb/main.go::runServe:
//   1. shell env (already in os.Environ)
//   2. .env.local (only fills the gaps)
//
// So an operator can `export ANTHROPIC_API_KEY=...` for one-off runs
// and `.env.local` for persistent dev defaults without conflict.
func LoadDotEnv(path string) (loaded int, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		// Strip a single matching pair of quotes for ergonomics with
		// values that contain spaces or shell-special chars.
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if key == "" {
			continue
		}
		if _, already := os.LookupEnv(key); already {
			continue
		}
		_ = os.Setenv(key, val)
		loaded++
	}
	return loaded, sc.Err()
}
