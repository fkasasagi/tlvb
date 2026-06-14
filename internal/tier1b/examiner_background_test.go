package tier1b

import (
	"strings"
	"testing"
)

// TestBuildLLMContextExaminerBackground verifies the Tier 1B user-message
// context embeds the examiner background (and omits it when empty).
func TestBuildLLMContextExaminerBackground(t *testing.T) {
	prior := &priorContext{}
	bundle := &candidateBundle{}

	hctx := buildLLMContext("c1", "WS01 is the public web server", prior, bundle, nil)
	if hctx.ExaminerBackground == nil {
		t.Fatal("background must be embedded in llmContext")
	}
	if !strings.Contains(hctx.ExaminerBackground.Text, "WS01") {
		t.Errorf("background text not carried: %q", hctx.ExaminerBackground.Text)
	}

	if got := buildLLMContext("c1", "", prior, bundle, nil); got.ExaminerBackground != nil {
		t.Error("empty background must yield a nil ExaminerBackground (omitted from JSON)")
	}
}
