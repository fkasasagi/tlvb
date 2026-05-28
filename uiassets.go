// Package tlvb exists solely to embed the ui/ directory into the
// compiled binary. Go's //go:embed cannot reference paths outside the
// package directory, so a thin top-level package is required if we want
// `ui/` to live at the repo root (per CLAUDE.md and the WebUI spec).
//
// internal/web imports this package and serves the embedded FS.
package tlvb

import "embed"

// UI is the embedded front-end. The directory layout is:
//
//	ui/index.html
//	ui/static/style.css
//	ui/static/app.js
//
//go:embed all:ui
var UI embed.FS
