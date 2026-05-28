#!/usr/bin/env python3
"""Analyze token usage across a findevil case pipeline.

Reads TacticReport / synthesis / report JSON files from outputs/cases/<id>/
and produces a breakdown by tier, tactic, and model.

Usage:
    python3 scripts/usage_report.py                      # all cases
    python3 scripts/usage_report.py INC-2026-0003        # one case
    python3 scripts/usage_report.py --json                # machine-readable
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

CASES_DIR = Path("outputs/cases")

# Pricing per 1M tokens (USD). Rates as of 2026-05.
# cache_read is 10% of input price; cache_create is 125% (billed as input here).
PRICING: dict[str, dict[str, float]] = {
    "claude-opus-4-7":              {"input": 15.0,  "output": 75.0,  "cache_read": 1.50},
    "claude-opus-4-20250514":       {"input": 15.0,  "output": 75.0,  "cache_read": 1.50},
    "claude-sonnet-4-6":            {"input": 3.0,   "output": 15.0,  "cache_read": 0.30},
    "claude-sonnet-4-6-20250514":   {"input": 3.0,   "output": 15.0,  "cache_read": 0.30},
    "claude-haiku-4-5-20251001":    {"input": 0.80,  "output": 4.0,   "cache_read": 0.08},
}
FALLBACK_PRICING = {"input": 3.0, "output": 15.0, "cache_read": 0.30}


def estimate_cost(model: str, tok_in: int, tok_out: int, tok_cache: int) -> float:
    p = PRICING.get(model, FALLBACK_PRICING)
    return (tok_in * p["input"] + tok_out * p["output"] + tok_cache * p["cache_read"]) / 1_000_000


@dataclass
class Row:
    case_id: str = ""
    tier: str = ""
    component: str = ""
    model: str = ""
    tokens_input: int = 0
    tokens_output: int = 0
    cache_read: int = 0
    duration_sec: float = 0.0
    duration_api_ms: int = 0
    input_events: int = 0
    windows_total: int = 0
    iterations: int = 0
    status: str = ""
    findings_count: int = 0
    cost_usd: float = 0.0


def load_tactic_report(path: Path, case_id: str) -> Row | None:
    try:
        with open(path) as f:
            d = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    a = d.get("audit", {})
    model = a.get("model_id", "")
    tok_in = a.get("tokens_input", 0) or 0
    tok_out = a.get("tokens_output", 0) or 0
    tok_cache = a.get("cache_read_input_tokens", 0) or 0
    tactic_id = d.get("tactic_id", path.stem)
    stem = path.stem
    is_anomaly = stem == "anomaly_hunter" or tactic_id in ("anomaly_hunter", "ANOM")
    tier = "tier1.5" if is_anomaly else "tier1"
    name = d.get("tactic_name", stem)
    label = f"{tactic_id} {name}" if tactic_id != name else name
    return Row(
        case_id=case_id,
        tier=tier,
        component=label,
        model=model,
        tokens_input=tok_in,
        tokens_output=tok_out,
        cache_read=tok_cache,
        duration_sec=a.get("duration_seconds", 0) or 0,
        duration_api_ms=a.get("duration_api_ms", 0) or 0,
        input_events=a.get("input_events", 0) or 0,
        windows_total=a.get("windows_total", 0) or 0,
        iterations=a.get("iterations", 0) or 0,
        status=d.get("status", ""),
        findings_count=len(d.get("findings") or []),
        cost_usd=estimate_cost(model, tok_in, tok_out, tok_cache),
    )


def load_synthesis(path: Path, case_id: str) -> Row | None:
    try:
        with open(path) as f:
            d = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    a = d.get("audit", {})
    total_tok = a.get("total_tokens", 0) or 0
    return Row(
        case_id=case_id,
        tier="tier2",
        component="synthesizer",
        model="(see tier1 model)",
        tokens_input=0,
        tokens_output=total_tok,
        duration_sec=a.get("execution_time_seconds", 0) or 0,
        iterations=a.get("total_iterations", 0) or 0,
        status="completed",
    )


def load_case(case_dir: Path) -> list[Row]:
    case_id = case_dir.name
    rows: list[Row] = []
    findings_dir = case_dir / "findings"
    if findings_dir.is_dir():
        for f in sorted(findings_dir.glob("*.json")):
            row = load_tactic_report(f, case_id)
            if row:
                rows.append(row)
        # by-artifact/ subdirectories
        ba = findings_dir / "by-artifact"
        if ba.is_dir():
            for scope_dir in sorted(ba.iterdir()):
                if not scope_dir.is_dir():
                    continue
                for f in sorted(scope_dir.glob("*.json")):
                    row = load_tactic_report(f, case_id)
                    if row:
                        row.component = f"{row.component}@{scope_dir.name}"
                        rows.append(row)
    synth = case_dir / "synthesis.json"
    if synth.exists():
        row = load_synthesis(synth, case_id)
        if row:
            rows.append(row)
    return rows


def fmt_int(n: int) -> str:
    if n == 0:
        return "-"
    return f"{n:,}"


def fmt_dur(sec: float) -> str:
    if sec <= 0:
        return "-"
    if sec < 60:
        return f"{sec:.0f}s"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{int(m)}m{int(s)}s"
    h, mm = divmod(m, 60)
    return f"{int(h)}h{int(mm)}m"


def fmt_cost(usd: float) -> str:
    if usd <= 0:
        return "-"
    if usd < 0.01:
        return f"${usd:.4f}"
    return f"${usd:.3f}"


def print_table(rows: list[Row], show_case: bool):
    if not rows:
        print("(no data)")
        return

    headers = []
    if show_case:
        headers.append("case")
    headers += ["tier", "component", "model", "in_tok", "out_tok",
                "cache_rd", "events", "win", "iter", "duration", "cost", "status", "finds"]

    def make_cells(r: Row) -> list[str]:
        cells = []
        if show_case:
            cells.append(r.case_id)
        model_short = r.model.replace("claude-", "").replace("-20251001", "").replace("-20250514", "")
        cells += [
            r.tier, r.component, model_short,
            fmt_int(r.tokens_input), fmt_int(r.tokens_output), fmt_int(r.cache_read),
            fmt_int(r.input_events), fmt_int(r.windows_total), fmt_int(r.iterations),
            fmt_dur(r.duration_sec), fmt_cost(r.cost_usd), r.status,
            fmt_int(r.findings_count),
        ]
        return cells

    fmt_rows = [make_cells(r) for r in rows]
    widths = [max(len(h), *(len(row[i]) for row in fmt_rows))
              for i, h in enumerate(headers)]

    def line(cells: list[str]) -> str:
        parts = []
        for i, (c, w) in enumerate(zip(cells, widths)):
            parts.append(c.ljust(w) if i < 3 + (1 if show_case else 0) else c.rjust(w))
        return "  ".join(parts)

    print(line(headers))
    print(line(["-" * w for w in widths]))

    cur_tier = ""
    for r, cells in zip(rows, fmt_rows):
        if r.tier != cur_tier and cur_tier:
            print()
        cur_tier = r.tier
        print(line(cells))

    # Totals
    total_in = sum(r.tokens_input for r in rows)
    total_out = sum(r.tokens_output for r in rows)
    total_cache = sum(r.cache_read for r in rows)
    total_dur = sum(r.duration_sec for r in rows)
    total_cost = sum(r.cost_usd for r in rows)
    print()
    print(f"TOTAL  tokens: in={fmt_int(total_in)} out={fmt_int(total_out)} cache_rd={fmt_int(total_cache)}"
          f"  duration={fmt_dur(total_dur)}  est_cost={fmt_cost(total_cost)}")

    # Per-tier subtotal
    tiers: dict[str, dict] = {}
    for r in rows:
        t = tiers.setdefault(r.tier, {"in": 0, "out": 0, "cache": 0, "dur": 0.0, "cost": 0.0, "n": 0})
        t["in"] += r.tokens_input
        t["out"] += r.tokens_output
        t["cache"] += r.cache_read
        t["dur"] += r.duration_sec
        t["cost"] += r.cost_usd
        t["n"] += 1
    print()
    print("Per-tier subtotals:")
    for tier_name in sorted(tiers):
        t = tiers[tier_name]
        print(f"  {tier_name:8s}  components={t['n']:2d}  out_tok={fmt_int(t['out']):>8s}"
              f"  duration={fmt_dur(t['dur']):>7s}  cost={fmt_cost(t['cost'])}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("case_id", nargs="?", help="Case ID to analyze. Default: all cases.")
    ap.add_argument("--json", action="store_true", help="Output as JSON array.")
    ap.add_argument("--cases-dir", default=str(CASES_DIR), help="Override cases directory.")
    args = ap.parse_args()

    cases_dir = Path(args.cases_dir)
    if not cases_dir.is_dir():
        print(f"Cases directory not found: {cases_dir}", file=sys.stderr)
        sys.exit(1)

    if args.case_id:
        case_dirs = [cases_dir / args.case_id]
        if not case_dirs[0].is_dir():
            print(f"Case not found: {case_dirs[0]}", file=sys.stderr)
            sys.exit(1)
    else:
        case_dirs = sorted(d for d in cases_dir.iterdir() if d.is_dir())

    all_rows: list[Row] = []
    for d in case_dirs:
        all_rows.extend(load_case(d))

    if not all_rows:
        print("No reports found.")
        sys.exit(0)

    if args.json:
        import dataclasses
        json.dump([dataclasses.asdict(r) for r in all_rows], sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        show_case = len(case_dirs) > 1
        print(f"Cases: {', '.join(d.name for d in case_dirs)}")
        print()
        print_table(all_rows, show_case)


if __name__ == "__main__":
    main()
