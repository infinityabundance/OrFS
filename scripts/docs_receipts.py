#!/usr/bin/env python3
"""OrFS docs-from-receipts check.

Two independent verifications, both driven by scripts/docs-receipts.json:

1. Provenance / currency. Every receipt under evidence/receipts/ that records a
   source commit is compared with the repository HEAD. A receipt that records an
   older (ancestor) commit is reported as a distinct, clearly-labelled "stale"
   finding; receipts that are intentionally historical must be named in the
   config allowlist with a reason, otherwise they fail the check.

2. Doc -> evidence number citations. A curated mapping ties a doc citation (file
   + regex over the doc text + capture group) to a value in a machine-generated
   evidence JSON (a dotted/indexed path). The doc's stated number is compared
   with the evidence value within a per-citation tolerance; a mismatch fails.

Dependency-light: Python 3 standard library plus `git`. Exits non-zero when
anything fails, and prints an itemised report. Nothing is ever written to the
docs or to the evidence: this check only detects and reports drift.

Run it through scripts/check-docs-receipts.sh (it does not need Docker).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

MISSING = object()


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def git(root, *args):
    try:
        p = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True
        )
    except FileNotFoundError:
        return 127, "", "git executable not found on PATH"
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def parse_path(path):
    """Parse `a.b[3].c` / `a[k=v].c` into (name, [selectors]) segments."""
    segs = []
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)((?:\[[^\]]*\])*)", path):
        name = m.group(1)
        brackets = re.findall(r"\[([^\]]*)\]", m.group(2))
        segs.append((name, brackets))
    return segs


def resolve(obj, path):
    """Resolve a dotted/indexed path; return MISSING if any step is absent."""
    node = obj
    for name, brackets in parse_path(path):
        if not isinstance(node, dict) or name not in node:
            return MISSING
        node = node[name]
        for b in brackets:
            if re.fullmatch(r"-?\d+", b):
                idx = int(b)
                if not isinstance(node, list) or not (-len(node) <= idx < len(node)):
                    return MISSING
                node = node[idx]
            elif "=" in b:
                # The selector key may itself be a dotted path (e.g. summary.label).
                key, want = b.split("=", 1)
                kparts = key.split(".")
                found = MISSING
                if isinstance(node, list):
                    for el in node:
                        probe = el
                        for kp in kparts:
                            if not isinstance(probe, dict) or kp not in probe:
                                probe = MISSING
                                break
                            probe = probe[kp]
                        if probe is MISSING:
                            continue
                        if str(probe) == want:
                            found = el
                            break
                        try:
                            if float(probe) == float(want):
                                found = el
                                break
                        except (TypeError, ValueError):
                            pass
                if found is MISSING:
                    return MISSING
                node = found
            else:
                return MISSING
    return node


def parse_num(raw):
    """Parse a doc number, tolerating thin/regular spaces as thousands separators."""
    t = re.sub(r"[\s\u00a0\u202f\u2009]+", "", raw)
    return float(t)


def pct(diff, base):
    if base == 0:
        return "n/a"
    return "%.2f%%" % (100.0 * diff / abs(base))


# --------------------------------------------------------------------------- #
# checks
# --------------------------------------------------------------------------- #
def check_provenance(root, cfg):
    """Return (records, hard_failures)."""
    pv = cfg.get("provenance", {})
    receipts_dir = pv.get("receipts_dir", "evidence/receipts")
    commit_fields = pv.get("commit_fields", ["orfs_git_commit"])
    allow = {}
    for e in pv.get("allowlist", []):
        allow[(e.get("receipt"), e.get("field"))] = e.get("reason", "")

    rc, head_full, err = git(root, "rev-parse", "HEAD")
    if rc != 0 or not head_full:
        return [], ["cannot resolve repository HEAD via git: %s" % (err or "unknown")]

    rdir = os.path.join(root, receipts_dir)
    records = []
    failures = []
    if not os.path.isdir(rdir):
        return [], ["receipts directory not found: %s" % receipts_dir]

    for fn in sorted(os.listdir(rdir)):
        if not fn.endswith(".json"):
            continue
        rel = os.path.join(receipts_dir, fn)
        try:
            with open(os.path.join(rdir, fn), encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError) as exc:
            records.append(
                {
                    "receipt": rel,
                    "status": "error",
                    "detail": "unreadable/invalid JSON: %s" % exc,
                }
            )
            failures.append("%s: unreadable/invalid JSON: %s" % (rel, exc))
            continue
        if not isinstance(doc, dict):
            continue
        for field in commit_fields:
            if field not in doc:
                continue
            val = str(doc[field])
            rec = {"receipt": rel, "field": field, "commit": val, "status": "?"}
            key = (fn, field)
            if key in allow:
                rec["allowlisted"] = allow[key]
            exists = git(root, "cat-file", "-e", val + "^{commit}")[0] == 0
            if not exists:
                rec["status"] = "unknown"
            else:
                _, full, _ = git(root, "rev-parse", val + "^{commit}")
                if full == head_full:
                    rec["status"] = "current"
                elif git(root, "merge-base", "--is-ancestor", full, "HEAD")[0] == 0:
                    _, cnt, _ = git(root, "rev-list", "--count", full + "..HEAD")
                    rec["status"] = "stale"
                    rec["behind"] = int(cnt) if cnt.isdigit() else None
                else:
                    rec["status"] = "diverged"
            if rec["status"] == "current":
                rec["severity"] = "ok"
            elif rec.get("allowlisted"):
                rec["severity"] = "allowed"
            else:
                rec["severity"] = "fail"
                if rec["status"] == "stale":
                    failures.append(
                        "%s: %s=%s is %s commit(s) behind HEAD (stale)"
                        % (rel, field, val, rec.get("behind"))
                    )
                elif rec["status"] == "unknown":
                    failures.append(
                        "%s: %s=%s is not a commit in this repository (unknown)"
                        % (rel, field, val)
                    )
                else:
                    failures.append(
                        "%s: %s=%s is not an ancestor of HEAD (diverged)"
                        % (rel, field, val)
                    )
            records.append(rec)
    return records, failures


def check_citations(root, cfg):
    """Return (checks, hard_failures)."""
    default = cfg.get("default_tolerance", {"rel": 0.05, "abs": 0.0})
    checks = []
    failures = []

    for cit in cfg.get("citations", []):
        cid = cit.get("id", "<unnamed>")
        docfile = cit["doc"]
        base = {
            "id": cid,
            "doc": docfile,
            "section": cit.get("section", ""),
            "claim": cit.get("claim", ""),
        }
        try:
            with open(os.path.join(root, docfile), encoding="utf-8") as f:
                text = f.read()
        except OSError as exc:
            checks.append(dict(base, ok=False, error="cannot read doc: %s" % exc))
            failures.append("%s: cannot read doc %s: %s" % (cid, docfile, exc))
            continue

        m = re.search(cit["regex"], text)
        if not m:
            checks.append(
                dict(base, ok=False, error="citation anchor not found (regex did not match)")
            )
            failures.append(
                "%s: anchor not found in %s (doc may have been reworded)"
                % (cid, docfile)
            )
            continue

        if cit.get("kind") == "set":
            raw = m.group(cit["fields"][0]["group"])
            want = sorted(set(int(x) for x in re.split(r"[/,\s]+", raw) if x))
            evfile = cit["fields"][0]["evidence"]
            try:
                with open(os.path.join(root, evfile), encoding="utf-8") as f:
                    ev = json.load(f)
            except (OSError, ValueError) as exc:
                checks.append(dict(base, ok=False, error="evidence unreadable: %s" % exc))
                failures.append("%s: evidence %s unreadable: %s" % (cid, evfile, exc))
                continue
            coll = cit["fields"][0].get("collect", {})
            arr = resolve(ev, coll.get("array", ""))
            if not isinstance(arr, list):
                checks.append(dict(base, ok=False, error="evidence array not found"))
                failures.append("%s: evidence array %s not found" % (cid, coll.get("array")))
                continue
            got = sorted(
                set(int(e[coll["field"]]) for e in arr if isinstance(e, dict) and coll["field"] in e)
            )
            entry = dict(
                base,
                ok=(want == got),
                label=cit["fields"][0].get("label", "set"),
                doc_values=want,
                evidence_values=got,
            )
            if want != got:
                failures.append("%s: reader set doc=%s != evidence=%s" % (cid, want, got))
            checks.append(entry)
            continue

        for field in cit.get("fields", []):
            g = field["group"]
            if g > m.re.groups:
                checks.append(dict(base, ok=False, error="capture group %d missing" % g))
                failures.append("%s: capture group %d not present in match" % (cid, g))
                continue
            raw = m.group(g)
            label = field.get("label", field["path"])
            try:
                docnum = parse_num(raw)
            except ValueError:
                checks.append(dict(base, ok=False, label=label, error="doc value not numeric: %r" % raw))
                failures.append("%s/%s: doc capture %r is not numeric" % (cid, label, raw))
                continue

            evfile = field["evidence"]
            try:
                with open(os.path.join(root, evfile), encoding="utf-8") as f:
                    ev = json.load(f)
            except (OSError, ValueError) as exc:
                checks.append(dict(base, ok=False, label=label, error="evidence unreadable: %s" % exc))
                failures.append("%s/%s: evidence %s unreadable: %s" % (cid, label, evfile, exc))
                continue

            got = resolve(ev, field["path"])
            if got is MISSING:
                checks.append(
                    dict(base, ok=False, label=label, error="evidence path not found: %s" % field["path"])
                )
                failures.append(
                    "%s/%s: evidence path %s not found in %s"
                    % (cid, label, field["path"], evfile)
                )
                continue
            if not isinstance(got, (int, float)):
                checks.append(dict(base, ok=False, label=label, error="evidence value not numeric: %r" % (got,)))
                failures.append("%s/%s: evidence value %r is not numeric" % (cid, label, got))
                continue

            want = docnum * field.get("doc_multiplier", 1)
            gotv = float(got) * field.get("evidence_multiplier", 1)
            rel = field.get("rel", default["rel"])
            abs_tol = field.get("abs", default["abs"])
            diff = abs(want - gotv)
            tol = abs_tol + rel * abs(gotv)
            ok = diff <= tol
            checks.append(
                dict(
                    base,
                    ok=ok,
                    label=label,
                    doc_raw=raw,
                    doc_value=want,
                    evidence_value=gotv,
                    rel_diff=diff / abs(gotv) if gotv else None,
                    tolerance={"rel": rel, "abs": abs_tol},
                )
            )
            if not ok:
                failures.append(
                    "%s/%s: doc=%s evidence=%s (%s off, tol %s)"
                    % (
                        cid,
                        label,
                        ("%g" % want),
                        ("%g" % gotv),
                        pct(diff, gotv),
                        ("rel %g + abs %g" % (rel, abs_tol)),
                    )
                )
    return checks, failures


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def report_human(root, head, prov, cites, failures):
    out = []
    out.append("OrFS docs<->receipts check")
    out.append("  repo: %s" % root)
    out.append("  HEAD: %s" % (head or "unknown"))
    out.append("")

    out.append("== Provenance (%s/*.json recording a source commit) ==" % "evidence/receipts")
    if not prov:
        out.append("  (no receipts record a source commit)")
    for r in prov:
        if r.get("severity") == "allowed":
            behind = r.get("behind")
            extra = " (%s behind HEAD)" % behind if behind is not None else ""
            out.append(
                "  [allowed-historical] %s :: %s = %s%s\n      reason: %s"
                % (r["receipt"], r["field"], r["commit"], extra, r.get("allowlisted", ""))
            )
        elif r["status"] == "current":
            out.append(
                "  [current] %s :: %s = %s" % (r["receipt"], r["field"], r["commit"])
            )
        elif r["status"] == "stale":
            out.append(
                "  [STALE] %s :: %s = %s (%s commit(s) behind HEAD)  -> FAIL"
                % (r["receipt"], r["field"], r["commit"], r.get("behind"))
            )
        elif r["status"] == "unknown":
            out.append(
                "  [UNKNOWN] %s :: %s = %s (not a commit in this repo)  -> FAIL"
                % (r["receipt"], r["field"], r["commit"])
            )
        elif r["status"] == "diverged":
            out.append(
                "  [DIVERGED] %s :: %s = %s (not an ancestor of HEAD)  -> FAIL"
                % (r["receipt"], r["field"], r["commit"])
            )
        else:
            out.append("  [ERROR] %s :: %s" % (r["receipt"], r.get("detail", "error")))
    out.append("")

    out.append("== Citations (docs -> evidence numbers) ==")
    if not cites:
        out.append("  (no citations configured)")
    for c in cites:
        loc = "%s %s" % (c["doc"], c.get("section", ""))
        loc = loc.strip()
        if c.get("error"):
            out.append("  [ERROR]    %s [%s] %s" % (loc, c["id"], c["error"]))
        elif "doc_value" in c:
            state = "OK      " if c["ok"] else "MISMATCH"
            rdiff = (
                pct(abs(c["doc_value"] - c["evidence_value"]), c["evidence_value"])
                if c.get("evidence_value")
                else "n/a"
            )
            out.append(
                "  [%s] %s [%s]\n      %s: doc=%g evidence=%g (%s)"
                % (state, loc, c["id"], c["label"], c["doc_value"], c["evidence_value"], rdiff)
            )
        elif "doc_values" in c:
            state = "OK      " if c["ok"] else "MISMATCH"
            out.append(
                "  [%s] %s [%s]\n      %s: doc=%s evidence=%s"
                % (state, loc, c["id"], c["label"], c["doc_values"], c["evidence_values"])
            )
        else:
            out.append("  [ERROR]    %s [%s]" % (loc, c["id"]))
    out.append("")

    n_ok = sum(1 for c in cites if c.get("ok"))
    n_bad = len(cites) - n_ok
    out.append(
        "Summary: provenance %d record(s) (%d failing); citations %d check value(s) (%d ok, %d failing)"
        % (
            len(prov),
            sum(1 for r in prov if r.get("severity") == "fail") + sum(1 for r in prov if r["status"] == "error"),
            len(cites),
            n_ok,
            n_bad,
        )
    )
    out.append("RESULT: %s (%d failing item(s))" % ("FAIL" if failures else "PASS", len(failures)))
    if failures:
        out.append("")
        out.append("Failures:")
        for f in failures:
            out.append("  - %s" % f)
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="OrFS docs-from-receipts check")
    ap.add_argument("--root", default=os.getcwd())
    ap.add_argument("--config", required=True)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)

    _, head, _ = git(root, "rev-parse", "--short", "HEAD")
    prov, prov_fail = check_provenance(root, cfg)
    cites, cite_fail = check_citations(root, cfg)
    failures = prov_fail + cite_fail

    if args.json:
        print(
            json.dumps(
                {
                    "root": root,
                    "head": head,
                    "provenance": prov,
                    "citations": cites,
                    "failures": failures,
                    "result": "FAIL" if failures else "PASS",
                },
                indent=2,
            )
        )
    else:
        print(report_human(root, head, prov, cites, failures))

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
