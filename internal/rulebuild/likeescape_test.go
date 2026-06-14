package rulebuild

import "testing"

func TestEscapeLikeLiterals(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "interior underscore is escaped",
			in:   "x ILIKE '%ASP_%'",
			want: `x ILIKE '%ASP\_%' ESCAPE '\'`,
		},
		{
			name: "no underscore is left untouched",
			in:   "x ILIKE '%Webshell%'",
			want: "x ILIKE '%Webshell%'",
		},
		{
			name: "percent wildcards are preserved",
			in:   "x ILIKE '%ASP_Agent%'",
			want: `x ILIKE '%ASP\_Agent%' ESCAPE '\'`,
		},
		{
			name: "case-sensitive LIKE handled too",
			in:   "x LIKE 'PHP_shell%'",
			want: `x LIKE 'PHP\_shell%' ESCAPE '\'`,
		},
		{
			name: "NOT ILIKE handled",
			in:   "x NOT ILIKE '%a_b%'",
			want: `x NOT ILIKE '%a\_b%' ESCAPE '\'`,
		},
		{
			name: "existing backslash is doubled so it stays literal",
			in:   `x ILIKE '%\Temp\a_b%'`,
			want: `x ILIKE '%\\Temp\\a\_b%' ESCAPE '\'`,
		},
		{
			name: "idempotent: already-escaped pattern is unchanged",
			in:   `x ILIKE '%ASP\_%' ESCAPE '\'`,
			want: `x ILIKE '%ASP\_%' ESCAPE '\'`,
		},
		{
			name: "json path argument is not a LIKE operand and is left alone",
			in:   "json_extract_string(payload_json, '$.PayloadData1') ILIKE '%ASP_%'",
			want: `json_extract_string(payload_json, '$.PayloadData1') ILIKE '%ASP\_%' ESCAPE '\'`,
		},
		{
			name: "multiple patterns in one statement",
			in:   "a ILIKE '%ASP_%' OR b ILIKE '%Webshell%' OR c ILIKE '%PHP_%'",
			want: `a ILIKE '%ASP\_%' ESCAPE '\' OR b ILIKE '%Webshell%' OR c ILIKE '%PHP\_%' ESCAPE '\'`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EscapeLikeLiterals(tc.in); got != tc.want {
				t.Errorf("EscapeLikeLiterals(%q)\n got: %q\nwant: %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestEscapeLikeLiteralsIdempotent guards the property that running the
// transform twice equals running it once — the import path and the build
// pipeline can both apply it without double-escaping.
func TestEscapeLikeLiteralsIdempotent(t *testing.T) {
	in := "a ILIKE '%ASP_%' OR b LIKE 'PHP_x%' OR c ILIKE '%clean%'"
	once := EscapeLikeLiterals(in)
	twice := EscapeLikeLiterals(once)
	if once != twice {
		t.Errorf("not idempotent:\n once: %q\ntwice: %q", once, twice)
	}
}
