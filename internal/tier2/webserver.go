package tier2

import (
	"context"
	"database/sql"
	"fmt"
)

// webserver.go corroborates web-server presence from the filesystem (MFT), not
// just from parsed web logs. A web shell / public-facing-app exploit needs a web
// server; the parsed-artifact check (containsWebArtifact) only fires when a
// web-log parser ran, which it may not have. Querying the MFT for a document root
// or a live IIS config is the stronger, parser-independent signal — and the one a
// human falls back to (the distrib_winrm_spray "web shell" was an FP precisely
// because that host had neither web logs nor a web root).

// detectWebServerOnDisk reports whether the case MFT shows a live web-server
// document root or config. It pre-filters likely rows in SQL (cheap over a large
// MFT) and applies the precise OS-component-store exclusions in
// pathIndicatesWebServer, so dormant .NET/WinSxS ASP.NET skeleton files do not
// count. Best-effort: a DB failure returns (false, err) and the caller treats the
// case as not-known-to-have a web server.
func detectWebServerOnDisk(ctx context.Context, db *sql.DB, caseID string) (bool, error) {
	const q = `SELECT json_extract_string(payload_json, '$.ParentPath'),
	                  json_extract_string(payload_json, '$.FileName')
	             FROM unified_events
	            WHERE case_id = ? AND artifact_id = 'mft'
	              AND (
	                lower(json_extract_string(payload_json, '$.ParentPath')) LIKE '%inetpub%'
	                OR lower(json_extract_string(payload_json, '$.ParentPath')) LIKE '%htdocs%'
	                OR lower(json_extract_string(payload_json, '$.ParentPath')) LIKE '%webapps%'
	                OR lower(json_extract_string(payload_json, '$.ParentPath')) LIKE '%nginx%'
	                OR lower(json_extract_string(payload_json, '$.FileName')) = 'applicationhost.config'
	              )`
	rows, err := db.QueryContext(ctx, q, caseID)
	if err != nil {
		return false, fmt.Errorf("query mft web-root: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var parentPath, fileName sql.NullString
		if err := rows.Scan(&parentPath, &fileName); err != nil {
			return false, err
		}
		if pathIndicatesWebServer(parentPath.String, fileName.String) {
			return true, nil
		}
	}
	return false, rows.Err()
}
