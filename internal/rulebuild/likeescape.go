package rulebuild

import (
	"regexp"
	"strings"
)

// likeLiteralRe matches a LIKE / ILIKE / NOT LIKE / NOT ILIKE operator followed
// by a single-quoted pattern literal, plus any ESCAPE clause that already
// follows it. Group 1 = the operator, group 2 = the pattern body (with ”
// doubled quotes preserved), group 3 = an existing " ESCAPE 'x'" clause (empty
// when absent). The body alternation [^']|” keeps embedded ” literals intact.
var likeLiteralRe = regexp.MustCompile(`(?i)\b((?:NOT\s+)?I?LIKE)\s+'((?:[^']|'')*)'(\s+ESCAPE\s+'(?:[^']|'')*')?`)

// EscapeLikeLiterals makes a literal '_' inside a LIKE/ILIKE pattern match a
// literal underscore instead of the SQL single-character wildcard.
//
// Sigma `contains` / `startswith` values routinely carry literal underscores
// (ASP_, JSP_, PHP_, Backdoor_), but the LLM SQL translator emits them into
// ILIKE patterns unescaped, where '_' silently means "any one character". The
// canonical failure: `ILIKE '%ASP_%'` matches "ServiceName: RasPppoe ..." (a
// Kernel-PnP 410 device event), turning the Antivirus Web Shell signature into
// a false positive. Across the corpus this affects every pattern with an
// interior underscore.
//
// For each LIKE/ILIKE 'pattern' whose body contains '_', we escape existing
// backslashes ('\' -> '\\') and underscores ('_' -> '\_'), leave '%' untouched
// (so Sigma '*' wildcards stay wildcards), and append ESCAPE '\'. Patterns with
// no '_' are left byte-for-byte unchanged; so are patterns that already carry
// an ESCAPE clause, which keeps the transform idempotent.
//
// Trade-off: a Sigma '?' single-char wildcard rendered as '_' becomes literal,
// a tiny recall loss that is overwhelmingly worth the false-positive reduction
// — '?' is vanishingly rare in the rule corpus, literal '_' is common.
func EscapeLikeLiterals(sqlText string) string {
	return likeLiteralRe.ReplaceAllStringFunc(sqlText, func(m string) string {
		g := likeLiteralRe.FindStringSubmatch(m)
		op, body, existingEscape := g[1], g[2], g[3]
		if existingEscape != "" || !strings.Contains(body, "_") {
			return m // already escaped, or nothing to escape — leave as-is
		}
		body = strings.ReplaceAll(body, `\`, `\\`)
		body = strings.ReplaceAll(body, "_", `\_`)
		return op + " '" + body + `' ESCAPE '\'`
	})
}
