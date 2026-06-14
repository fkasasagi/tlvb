package tier2

import (
	"strings"
	"testing"
)

func TestPathIndicatesWebServer(t *testing.T) {
	cases := []struct {
		name       string
		parentPath string
		fileName   string
		want       bool
	}{
		{"iis wwwroot", `.\inetpub\wwwroot`, "index.html", true},
		{"iis wwwroot file", `.\inetpub\wwwroot\app`, "shell.aspx", true},
		{"apache htdocs", `.\Apache24\htdocs`, "info.php", true},
		{"tomcat webapps", `.\Tomcat\webapps\ROOT`, "x.jsp", true},
		{"nginx html", `.\nginx\html`, "index.html", true},
		{"live applicationHost.config", `.\Windows\System32\inetsrv\config`, "applicationHost.config", true},

		// The distrib_winrm_spray reality: ASP.NET / IIS skeleton in the OS
		// component store is NOT a served web server.
		{"winsxs applicationHost template", `.\Windows\WinSxS\amd64_microsoft-windows-i..raries-servercommon_x\`, "applicationHost.config", false},
		{"dotnet aspnet admin files", `.\Windows\Microsoft.NET\Framework64\v4.0.30319\ASP.NETWebAdminFiles`, "default.aspx", false},
		{"winsxs aspx", `.\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_x`, "certrqxt.asp", false},
		{"servicing package", `.\Windows\servicing\Packages`, "x.aspx", false},
		// Windows ships web-shaped folders under C:\Windows that are NOT served
		// sites — the CloudExperienceHost OOBE UI is the real-data FP that broke
		// the first cut of this check.
		{"cloudexperiencehost webapps", `.\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\webapps\AntiTheft`, "view.js", false},

		{"unrelated", `.\Users\admin\Documents`, "notes.txt", false},
		{"empty", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pathIndicatesWebServer(c.parentPath, c.fileName); got != c.want {
				t.Errorf("pathIndicatesWebServer(%q,%q)=%v want %v", c.parentPath, c.fileName, got, c.want)
			}
		})
	}
}

func TestUncorroboratedClaimAliases(t *testing.T) {
	// No web server + brute-force burst + clock reversal → all three demoted.
	ctx := groundingContext{
		HasWebArtifact:      false,
		BruteForcedAccounts: map[string]bool{"administrator": true},
		ClockReversed:       true,
	}
	got := uncorroboratedClaimAliases(ctx)
	for _, label := range []string{"Web shell", "Pass-the-Hash", "attacker timestomp"} {
		if _, ok := got[label]; !ok {
			t.Errorf("expected %q uncorroborated, got keys %v", label, keysOf(got))
		}
	}

	// With a web server present, the web-shell claim is corroboratable → not listed.
	ctx.HasWebArtifact = true
	got = uncorroboratedClaimAliases(ctx)
	if _, ok := got["Web shell"]; ok {
		t.Errorf("web shell should be corroboratable when a web server exists")
	}
	// PtH still demoted (brute force present).
	if _, ok := got["Pass-the-Hash"]; !ok {
		t.Errorf("PtH should stay uncorroborated with a brute-force burst")
	}

	// Clean case: nothing demoted.
	got = uncorroboratedClaimAliases(groundingContext{HasWebArtifact: true})
	if len(got) != 0 {
		t.Errorf("clean case should have no uncorroborated claims, got %v", keysOf(got))
	}
}

func TestUncorroboratedClaimAliasesFromTechniques(t *testing.T) {
	unconfirmed := []MITREEntry{{Technique: "T1505.003"}, {Technique: "T1059.001"}}
	got := uncorroboratedClaimAliasesFromTechniques(unconfirmed)
	if _, ok := got["Web shell"]; !ok {
		t.Errorf("T1505.003 unconfirmed should mark Web shell, got %v", keysOf(got))
	}
	if _, ok := got["Pass-the-Hash"]; ok {
		t.Errorf("no T1550.002 → PtH should not be marked")
	}
}

func TestReframeResolvedOpenQuestions(t *testing.T) {
	aliases := uncorroboratedClaimAliases(groundingContext{HasWebArtifact: false})
	questions := []string{
		"Defender が Web シェルとして検知したファイルのパス・ハッシュ・配置経路を特定し、初期アクセスベクターを確定する。",
		"WS01 自体がどのように侵害されたかを特定する。",
		"別の Web シェル関連の問い（重複）。", // second web-shell question must collapse
	}
	got := reframeResolvedOpenQuestions(questions, aliases, true)

	// The unrelated WS01 question survives verbatim.
	if !containsSubstr(got, "WS01 自体") {
		t.Errorf("unrelated question dropped: %v", got)
	}
	// No surviving question still asks to "特定する" the web shell.
	for _, q := range got {
		if strings.Contains(q, "Web シェルとして検知したファイルのパス") {
			t.Errorf("web-shell hunt question survived: %q", q)
		}
	}
	// Exactly one resolved note for the web shell (deduped).
	n := 0
	for _, q := range got {
		if strings.Contains(q, "【自動裏取り済】") && strings.Contains(q, "Web シェル") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected exactly 1 resolved web-shell note, got %d: %v", n, got)
	}
}

func TestReframeResolvedOpenQuestionsNoop(t *testing.T) {
	questions := []string{"通常の問い"}
	if got := reframeResolvedOpenQuestions(questions, nil, true); len(got) != 1 || got[0] != "通常の問い" {
		t.Errorf("nil aliases must be a no-op, got %v", got)
	}
}

func TestReframeOpenQuestionsSynth(t *testing.T) {
	aliases := uncorroboratedClaimAliases(groundingContext{HasWebArtifact: false})
	s := OpenQuestionsSynthesis{
		Critical:        []string{"Web シェルのパス・ハッシュを特定して初期アクセスを確定する。", "時刻巻き戻しを再アンカーする。"},
		NeedsCollection: []string{"AppLocker 8003 の詳細を取得する。"},
	}
	got := reframeOpenQuestionsSynth(s, aliases, true)

	for _, q := range got.Critical {
		if strings.Contains(q, "Web シェル") && !strings.Contains(q, "【自動裏取り済】") {
			t.Errorf("web-shell item should be removed from critical, got %q", q)
		}
	}
	// The non-web-shell critical item survives.
	if !containsSubstr(got.Critical, "再アンカー") {
		t.Errorf("unrelated critical item dropped: %v", got.Critical)
	}
	// A resolved note landed in supplementary.
	if !containsSubstr(got.Supplementary, "【自動裏取り済】") {
		t.Errorf("expected resolved note in supplementary, got %v", got.Supplementary)
	}
}

func TestUncorroboratedClaimDirectives(t *testing.T) {
	aliases := uncorroboratedClaimAliases(groundingContext{
		HasWebArtifact:      false,
		BruteForcedAccounts: map[string]bool{"admin": true},
	})
	linesJA := uncorroboratedClaimDirectives(aliases, true)
	joined := strings.Join(linesJA, "\n")
	if !strings.Contains(joined, "Web シェル") || !strings.Contains(joined, "Pass-the-Hash") {
		t.Errorf("expected web-shell + PtH directives, got %v", linesJA)
	}
	// English variant.
	linesEN := uncorroboratedClaimDirectives(aliases, false)
	if !strings.Contains(strings.Join(linesEN, "\n"), "web shell is UNCORROBORATED") {
		t.Errorf("expected EN web-shell directive, got %v", linesEN)
	}
	// Empty when nothing uncorroborated.
	if len(uncorroboratedClaimDirectives(nil, true)) != 0 {
		t.Errorf("nil aliases → no directives")
	}
}

func keysOf(m map[string][]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func containsSubstr(haystack []string, sub string) bool {
	for _, s := range haystack {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
