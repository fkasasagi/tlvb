package tier2

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestClaudeCLIErrorSurfacesStdout pins what a failed CLI invocation tells the
// operator.
//
// A real run lost a cluster to `exec: exit status 1 (stderr: )` and nothing
// else — no indication of whether the model refused, the prompt was rejected,
// or the request never left the machine. The CLI reports that class of failure
// as JSON on STDOUT with an empty stderr, which the error was throwing away.
// Diagnosing it took three separate experiments; the message should have
// carried the answer.
func TestClaudeCLIErrorSurfacesStdout(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "fake-claude.sh")
	script := "#!/bin/sh\n" +
		"cat >/dev/null\n" +
		`echo '{"is_error":true,"result":"Usage limit reached"}'` + "\n" +
		"exit 1\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := Config{ClaudeBinary: fake, PerClusterTimeout: time.Minute}
	_, err := callClaudeCLI(context.Background(), cfg, "sys", "user")
	if err == nil {
		t.Fatal("expected an error from a CLI exiting 1")
	}
	msg := err.Error()
	if !strings.Contains(msg, "Usage limit reached") {
		t.Errorf("error does not carry the CLI's stdout, so the operator still cannot "+
			"tell why it failed: %q", msg)
	}
	// The duration separates a fast rejection from a real analysis that died
	// part-way — the single most useful signal when triaging a batch of these.
	if !strings.Contains(msg, "after ") {
		t.Errorf("error does not report how long the CLI ran: %q", msg)
	}
}
