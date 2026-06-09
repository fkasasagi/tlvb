package mcp

import (
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/server"
)

// TestMCPSurfaceIsReadOnly enumerates every tool the TLVB MCP server registers
// and asserts the whole surface is read-only — the architectural guarantee in
// CLAUDE.md ("execute_shell is NEVER exposed to MCP" / "MCP functions are
// read-only only"). If anyone adds a mutating or shell tool, this test fails.
//
// It builds the server's tool registry directly (registerTools only takes
// method values; it touches no DB/catalog field at registration time), so the
// test needs no DuckDB file or artifacts.yaml.
func TestMCPSurfaceIsReadOnly(t *testing.T) {
	s := &Server{
		mcp: server.NewMCPServer("test", "test", server.WithToolCapabilities(false)),
	}
	s.registerTools()

	tools := s.mcp.ListTools()
	if len(tools) < 15 {
		t.Fatalf("expected the full read-only tool set (>=15), got %d", len(tools))
	}

	// No tool name may imply mutation, execution, or review-approval.
	banned := []string{
		"exec", "shell", "spawn", "command", "write", "insert", "update",
		"delete", "drop", "alter", "attach", "pragma", "create", "register",
		"ingest", "mutate", "approve", "reject", "import",
	}
	for name := range tools {
		low := strings.ToLower(name)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("MCP exposes a tool whose name implies a non-read-only capability: %q (matched %q)", name, b)
			}
		}
	}

	// Approval/parsing/registration must never be reachable as a tool — the LLM
	// can only READ review state, never change it (human-only review gates).
	for _, forbidden := range []string{
		"execute_shell", "run_parser", "run_tier1a", "approve_finding",
		"reject_finding", "set_review", "register_case", "register_evidence",
		"delete_case",
	} {
		if _, ok := tools[forbidden]; ok {
			t.Errorf("forbidden mutating tool is registered: %q", forbidden)
		}
	}

	// Sanity: the known read-only tools really are present (registration ran).
	for _, want := range []string{"list_cases", "get_unified_events", "list_findings", "get_synthesis"} {
		if _, ok := tools[want]; !ok {
			t.Errorf("expected read-only tool %q to be registered", want)
		}
	}
}
