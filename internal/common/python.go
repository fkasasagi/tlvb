package common

import (
	"os"
	"path/filepath"
)

// ResolvePython returns the python3 interpreter path the parser
// orchestrator should be invoked with.
//
// Resolution order:
//  1. $TLVB_PYTHON (explicit override — useful for nix / conda setups)
//  2. <cwd>/.venv/bin/python3 (project-local venv created by scripts/setup.sh
//     on PEP 668 distros — Ubuntu 24.04+, Debian 12+, etc.)
//  3. "python3" (PATH lookup; system Python if no venv)
//
// Why this exists: Modern distros ship Python 3.12+ with PEP 668's
// externally-managed-environment marker, which causes plain
// `pip install duckdb` to be rejected. setup.sh works around this by
// creating ./.venv and installing duckdb there; this helper makes sure
// the Go binary's parser dispatcher actually uses that venv at runtime,
// so parsers can `import duckdb` without the user having to manually
// activate the venv.
func ResolvePython() string {
	if p := os.Getenv("TLVB_PYTHON"); p != "" {
		return p
	}
	cwd, err := os.Getwd()
	if err == nil {
		venvPy := filepath.Join(cwd, ".venv", "bin", "python3")
		if fi, err := os.Stat(venvPy); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return venvPy
		}
	}
	return "python3"
}
