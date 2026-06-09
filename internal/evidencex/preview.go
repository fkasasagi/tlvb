package evidencex

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// PreviewCaps bounds how much of each extracted file is fed back to the LLM.
type PreviewCaps struct {
	MaxTextBytes int // inline head for text files
	MaxHexBytes  int // raw bytes rendered as a hexdump for binary files
}

// DefaultCaps is a conservative default: 32 KiB of text or a 2 KiB hexdump.
// At ~4 chars/token that is ~8k tokens for text — enough to read a dropped
// script or a config file, small enough not to wreck prompt cost.
func DefaultCaps() PreviewCaps { return PreviewCaps{MaxTextBytes: 32 * 1024, MaxHexBytes: 2 * 1024} }

// FilePreview is the bounded, render-ready view of one extracted file.
type FilePreview struct {
	Target    string
	NTFSPath  string
	Status    string
	Kind      string // text | binary | directory | missing
	Bytes     int64
	SHA256    string
	Content   string // text head or hexdump (empty for missing/directory)
	Truncated bool
	Note      string // human note for misses / directories
}

// Preview reads back an extracted file and produces a bounded view of it.
func Preview(r FileResult, caps PreviewCaps) FilePreview {
	p := FilePreview{
		Target: r.Target, NTFSPath: r.NTFSPath, Status: r.Status,
		Bytes: r.Bytes, SHA256: r.SHA256,
	}
	if r.Status != "ok" || r.ExtractedPath == "" {
		p.Kind = "missing"
		p.Note = missNote(r)
		return p
	}
	fi, err := os.Stat(r.ExtractedPath)
	if err != nil {
		p.Kind = "missing"
		p.Note = "extracted but unreadable: " + err.Error()
		return p
	}
	if fi.IsDir() {
		p.Kind = "directory"
		p.Note = fmt.Sprintf("directory extracted to %s (%d entries) — inspect via filesystem, not inlined",
			r.ExtractedPath, countDirEntries(r.ExtractedPath))
		return p
	}

	readCap := caps.MaxTextBytes
	if caps.MaxHexBytes > readCap {
		readCap = caps.MaxHexBytes
	}
	data, err := readN(r.ExtractedPath, readCap+1)
	if err != nil {
		p.Kind = "missing"
		p.Note = "extracted but unreadable: " + err.Error()
		return p
	}
	overRead := len(data) > readCap
	if overRead {
		data = data[:readCap]
	}

	if looksText(data) {
		p.Kind = "text"
		head := data
		if len(head) > caps.MaxTextBytes {
			head = head[:caps.MaxTextBytes]
			p.Truncated = true
		}
		p.Truncated = p.Truncated || overRead || (p.Bytes > int64(len(head)))
		p.Content = string(head)
	} else {
		p.Kind = "binary"
		raw := data
		if len(raw) > caps.MaxHexBytes {
			raw = raw[:caps.MaxHexBytes]
			p.Truncated = true
		}
		p.Truncated = p.Truncated || overRead || (p.Bytes > int64(len(raw)))
		p.Content = hexdump(raw)
	}
	return p
}

// BuildPreviewBlock renders previews into a text block for the next user
// message. It is self-describing so the LLM knows these are the files it asked
// for and how each turned out.
func BuildPreviewBlock(previews []FilePreview) string {
	var b strings.Builder
	b.WriteString("=== EXTRACTED FILES (you requested these; their contents follow) ===\n")
	b.WriteString("These were pulled read-only from the disk image so you can inspect them\n")
	b.WriteString("directly. Cite what you find in your finding descriptions.\n\n")
	for _, p := range previews {
		switch p.Kind {
		case "missing":
			fmt.Fprintf(&b, "--- %s — NOT AVAILABLE (%s) ---\n\n", p.Target, p.Note)
		case "directory":
			fmt.Fprintf(&b, "--- %s — %s ---\n\n", p.Target, p.Note)
		case "text":
			trunc := ""
			if p.Truncated {
				trunc = " [truncated]"
			}
			fmt.Fprintf(&b, "--- %s (text, %d bytes, sha256 %s)%s ---\n",
				p.Target, p.Bytes, short(p.SHA256), trunc)
			b.WriteString(p.Content)
			if !strings.HasSuffix(p.Content, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("\n")
		case "binary":
			trunc := ""
			if p.Truncated {
				trunc = " [hexdump truncated]"
			}
			fmt.Fprintf(&b, "--- %s (binary, %d bytes, sha256 %s)%s ---\n",
				p.Target, p.Bytes, short(p.SHA256), trunc)
			b.WriteString(p.Content)
			b.WriteString("\n")
		}
	}
	b.WriteString("=== END EXTRACTED FILES ===\n")
	return b.String()
}

func missNote(r FileResult) string {
	switch {
	case r.Error != "":
		return r.Status + ": " + r.Error
	case r.Status == "not_found":
		return "not present in the image"
	default:
		return r.Status
	}
}

// looksText returns true when data is plausibly human-readable text: no NUL
// bytes and a low share of control characters (tabs/newlines excepted).
func looksText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	// UTF-8 (incl. ASCII) with few control chars reads as text.
	ctrl := 0
	for _, b := range data {
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			ctrl++
		}
	}
	if float64(ctrl)/float64(len(data)) > 0.30 {
		return false
	}
	return utf8.Valid(data) || float64(ctrl)/float64(len(data)) <= 0.05
}

func readN(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	read := 0
	for read < n {
		m, err := f.Read(buf[read:])
		read += m
		if err != nil {
			break
		}
	}
	return buf[:read], nil
}

func countDirEntries(dir string) int {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(ents)
}

// hexdump renders bytes in a compact `offset  hex  ascii` layout (16/row).
func hexdump(data []byte) string {
	var b strings.Builder
	for off := 0; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		row := data[off:end]
		fmt.Fprintf(&b, "%08x  ", off)
		for i := 0; i < 16; i++ {
			if i < len(row) {
				fmt.Fprintf(&b, "%02x ", row[i])
			} else {
				b.WriteString("   ")
			}
			if i == 7 {
				b.WriteString(" ")
			}
		}
		b.WriteString(" |")
		for _, c := range row {
			if c >= 0x20 && c < 0x7f {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|\n")
	}
	return b.String()
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
