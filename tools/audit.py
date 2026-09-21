#!/usr/bin/env python3
"""Machine-checkable integrity and closure audit for a research workspace.

This verifies the control-plane ledger, state-machine legality, evidence integrity,
human-gate status, projection consistency and required ledgers. It does not decide
whether a security finding is valid; it proves whether the workspace is internally coherent.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from control_plane import (CYCLE_EDGES, EVENT_TYPES, HYP_EDGES, METHOD_SELF_ATTACK_ROWS,  # noqa: E402
                           REQUIRED_AUDIT_CLASSES, TECHNIQUE_RESULTS, ControlPlane,
                           asset_hosts, engagement_assets, evidence_id_ok,
                           host_in_scope, normalize_cycle_state, review_quote_problem,
                           scope_check, secret_pattern_hits, sha256_file)

CLOSURE_PROOF_PATH = Path("06_audits") / "CLOSURE-PROOF.md"
CLOSURE_PROOF_SECTIONS = (
    "SCOPE_PROOF", "SURFACE_COVERAGE", "AUTHORIZATION_COVERAGE", "WORKFLOW_COVERAGE",
    "TECHNIQUE_COVERAGE", "NEGATIVE_EVIDENCE", "VERIFIED_FINDINGS", "FALSE_POSITIVES",
    "BLOCKERS", "NOVELTY_CHECK", "DUPLICATE_CHECK", "STATE_INTEGRITY", "TOOL_LIMITATIONS",
    "HYGIENE", "CLEANUP", "REMAINING_UNKNOWNS", "FINAL_OPEN-HYPOTHESIS_AUDIT",
)
CLOSURE_TODO = "TODO(human)"
# Body validation: the marker is matched case/space-insensitively, and the body must
# survive invisible-character stripping with a real sentence's worth of content.
CLOSURE_TODO_RE = re.compile(r"todo\s*\(\s*human\s*\)", re.I)
CLOSURE_INVISIBLE_RE = re.compile(r"[\s\u200b-\u200f\u2060\ufeff]")
CLOSURE_WORD_SPLIT_RE = re.compile(r"[\s\u200b-\u200f\u2060\ufeff]+")
CLOSURE_LETTER_RE = re.compile(r"[A-Za-z]")
CLOSURE_MIN_CHARS = 20
CLOSURE_MIN_WORDS = 3


def closure_body_problem(name: str, body: str) -> str | None:
    """Why a required section body is not a real judgment, or None.

    Rule (documented in 07_AUDIT_CLOSURE.md): reject a `todo(human)` marker however it
    is cased/spaced; strip `[\\s\\u200b-\\u200f\\u2060\\ufeff]` and require >= 20 remaining
    characters; require either at least one letter or at least 3 whitespace-separated
    word tokens (a token counts as a word only when it contains a letter), so a body of
    punctuation, digits or repeated separators is not "content".
    """
    if CLOSURE_TODO_RE.search(body):
        return f"section {name} still contains a TODO(human) marker"
    cleaned = CLOSURE_INVISIBLE_RE.sub("", body)
    words = [tok for tok in CLOSURE_WORD_SPLIT_RE.split(body) if CLOSURE_LETTER_RE.search(tok)]
    if len(cleaned) < CLOSURE_MIN_CHARS or (len(words) < CLOSURE_MIN_WORDS and not CLOSURE_LETTER_RE.search(cleaned)):
        return (f"section {name} body is too thin for a judgment ({len(cleaned)} characters and "
                f"{len(words)} word tokens after invisible-character stripping; needs >= "
                f"{CLOSURE_MIN_CHARS} characters and either a letter or >= {CLOSURE_MIN_WORDS} words)")
    return None


CLOSURE_JUDGMENT_PROMPTS = {
    "SURFACE_COVERAGE": "map every applicable surface cell to a terminal state or a named blocker (cite ids)",
    "AUTHORIZATION_COVERAGE": "state which principals/roles were exercised per asset and what remains untested",
    "WORKFLOW_COVERAGE": "name every workflow touched and its disposition",
    "NEGATIVE_EVIDENCE": "list the negative conclusions with their validated controls",
    "FALSE_POSITIVES": "list the false positives and the control signature that rules each one out",
    "BLOCKERS": "name each blocker, its cause, and why it is not closable under this authorization",
    "NOVELTY_CHECK": "record the novelty comparison against program history and current public research",
    "DUPLICATE_CHECK": "record the duplicate comparison (root cause, primitive, representation, direction, impact)",
    "TOOL_LIMITATIONS": "record which tool failures limited coverage and how the gap was bounded",
    "CLEANUP": "record artifact/credential cleanup and the evidence that nothing sensitive remains",
    "REMAINING_UNKNOWNS": "list the open unknowns and why closure is still justified with them open",
    "FINAL_OPEN-HYPOTHESIS_AUDIT": "confirm every high-value legal hypothesis has an explicit disposition",
}


def parse_closure_proof(path: Path) -> tuple[dict[str, str], list[str]]:
    """Body text per required `##` section, plus any duplicated required headings.

    Parser rules (spec F2/F3/F7): fenced code blocks (``` toggling) are opaque — a
    fenced `## ...` line is never a heading and a fenced `TODO(human)` never counts;
    only headings in the required list switch the active section, so an unlisted `##`
    subheading is body text rather than a collection terminator; a required heading
    may appear only once.
    """
    bodies: dict[str, list[str]] = {name: [] for name in CLOSURE_PROOF_SECTIONS}
    duplicates: list[str] = []
    seen: set[str] = set()
    active: str | None = None
    fenced = False
    for line in path.read_text(errors="ignore").splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        if line.startswith("## "):
            heading = line[3:].strip()
            if heading in bodies:
                if heading in seen:
                    duplicates.append(heading)
                else:
                    seen.add(heading)
                    active = heading
                continue
            # An unlisted `##` subheading does not terminate the section: fall through
            # and keep it as body text for the active required section.
        if active is not None:
            bodies[active].append(line)
    return {name: "\n".join(lines).strip() for name, lines in bodies.items()}, duplicates


def closure_proof_failures(path: Path) -> list[str]:
    """Missing file, missing/empty or too-thin required section, unanswered TODO, or a duplicate."""
    if not path.is_file():
        return [f"{path.name} is missing — generate it with `python3 tools/audit.py <root> --emit-proof`"]
    sections, duplicates = parse_closure_proof(path)
    problems: list[str] = []
    for name in CLOSURE_PROOF_SECTIONS:
        body = sections[name]
        if not body:
            problems.append(f"section {name} is missing or empty")
            continue
        problem = closure_body_problem(name, body)
        if problem:
            problems.append(problem)
    problems.extend(f"duplicate section {name} — a required section must appear exactly once" for name in duplicates)
    return problems


def audit_fact_line(cls: str, item: dict, last_research_event: int) -> str:
    """One `class: STATUS (EV-..., [stale — re-record])` line for the proof skeleton.

    Currentness mirrors the closure rule: a PASS audit is current only when it was
    recorded after the last material (non-audit) event; otherwise the skeleton says so
    instead of printing a stale PASS as if it still held.
    """
    eid = str(item.get("event_id", "EV-0"))
    m = re.fullmatch(r"EV-(\d+)", eid)
    seq = int(m.group(1)) if m else 0
    stale = seq < last_research_event
    return f"{cls}: {item.get('status')} ({eid}{'; stale — re-record' if stale else ''})"


def closure_proof_text(root: Path) -> str:
    """Deterministic skeleton: mechanical facts filled, judgment sections carry TODO(human)."""
    cp = ControlPlane(root)
    events = cp._read_events()
    scope = scope_check(root, "https://closure-proof.invalid/")
    assets = engagement_assets(root)
    techniques = [
        f"{e.get('entity_id')}: {((e.get('payload') or {}).get('technique_family') or '?')} -> "
        f"{((e.get('payload') or {}).get('result') or '?')}"
        for e in events if e.get("type") == "TECHNIQUE_EVALUATED"
    ] or ["none recorded: no technique evaluations exist in this ledger"]
    hypotheses = [f"{hid}: {cp.hypothesis_status(hid)}" for hid in cp.all_hypothesis_ids()] or ["none recorded: no hypotheses exist in this workspace"]
    cycles = [f"cycle {cid}: {cp.cycle_status(cid)}" for cid in cp.all_cycle_ids()] or ["none recorded: no cycles exist in this workspace"]
    latest = latest_audit_events(events)
    last_research = latest_non_audit_event_id(events)
    audits = [audit_fact_line(cls, item, last_research) for cls, item in sorted(latest.items())] or ["none recorded: no audit classes have been recorded"]
    evidence = [f"{eid}: kind={meta.get('kind', '?')} path={meta.get('path', '?')}"
                for eid, meta in sorted(cp.evidence_index().items())] or ["none recorded: no evidence objects are registered"]
    facts = {
        "SCOPE_PROOF": [f"gate: {scope['gate']}",
                        f"assets: {json.dumps(list(assets or []), ensure_ascii=False)}"],
        "TECHNIQUE_COVERAGE": techniques,
        "VERIFIED_FINDINGS": hypotheses,
        "STATE_INTEGRITY": [*cycles, *audits],
        "HYGIENE": evidence,
    }
    lines = [
        "# Closure Proof",
        "",
        "Machine-emitted skeleton (`tools/audit.py --emit-proof`); replace every `TODO` prompt "
        "line with the judgment it asks for. `python3 tools/audit.py <root> --closure` must pass "
        "before closure; re-running with `--force` regenerates the skeleton and discards the prose.",
        "",
    ]
    for name in CLOSURE_PROOF_SECTIONS:
        lines += [f"## {name}", ""]
        if name in facts:
            lines += [f"- {fact}" for fact in facts[name]]
        else:
            lines.append(f"{CLOSURE_TODO}: {CLOSURE_JUDGMENT_PROMPTS[name]}")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def emit_closure_proof(root: Path, force: bool = False) -> Path:
    """Write/refresh the closure proof; never silently discard a filled proof without --force."""
    path = root / CLOSURE_PROOF_PATH
    if path.exists():
        if not path.is_file():
            raise ValueError(
                f"{path.relative_to(root).as_posix()} exists but is not a regular file — remove it "
                "(a directory or device cannot hold the closure proof) and re-run --emit-proof"
            )
        existing = path.read_text(errors="ignore")
        sections, _ = parse_closure_proof(path)
        unanswered = any(CLOSURE_TODO_RE.search(body) for body in sections.values())
        if existing.strip() and not unanswered and not force:
            raise ValueError(
                f"{path.relative_to(root).as_posix()} is already filled (no {CLOSURE_TODO} markers) — "
                "pass --force to overwrite it (the filled prose is discarded, the skeleton is regenerated)"
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(closure_proof_text(root))
    return path


def parse_status(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text(errors="ignore").splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        v = v.strip()
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out[k] = v
    return out



def parse_projection(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    out: dict[str, object] = {}
    for line in path.read_text(errors="ignore").splitlines():
        if ":" not in line or line.lstrip().startswith("#"):
            continue
        k, raw = line.split(":", 1)
        raw = raw.strip()
        try:
            out[k.strip()] = json.loads(raw)
        except json.JSONDecodeError:
            out[k.strip()] = raw.strip('\"')
    return out

def cycle_projection_status(root: Path, cid: str) -> str | None:
    p = root / "04_cycles" / cid / "plan.yaml"
    if not p.exists():
        return None
    return parse_status(p).get("status")


def hypothesis_projection_status(root: Path, hid: str) -> str | None:
    paths = [root / "03_hypotheses" / "active" / f"{hid}.yaml", root / "03_hypotheses" / "archive" / f"{hid}.yaml"]
    for p in paths:
        if p.exists():
            return parse_status(p).get("status")
    return None



def latest_audit_events(events: list[dict]) -> dict[str, dict]:
    latest: dict[str, dict] = {}
    for e in events:
        if e.get("type") != "AUDIT_RECORDED":
            continue
        p = e.get("payload", {})
        cls = p.get("class", e.get("entity_id"))
        if cls:
            latest[str(cls)] = {"status": str(p.get("status", "")), "time": e.get("time"), "event_id": e.get("event_id")}
    return latest


def latest_non_audit_event_id(events: list[dict]) -> int:
    ids = []
    for e in events:
        if e.get("type") == "AUDIT_RECORDED":
            continue
        m = re.fullmatch(r"EV-(\d+)", str(e.get("event_id", "")))
        if m:
            ids.append(int(m.group(1)))
    return max(ids, default=0)

def audit(root: Path, closure: bool = False) -> tuple[bool, dict]:
    cp = ControlPlane(root)
    errors: list[str] = []
    warnings: list[str] = []
    events = cp._read_events()

    # Ledger integrity: envelope shape, sequence, references, known types, and tamper-evident hash chain.
    required_event_fields = {"event_id", "time", "actor", "type", "entity_type", "entity_id", "evidence_refs", "payload", "prev_hash", "event_hash"}
    prev = "GENESIS"
    seen_ids = set()
    versioned_seen = False
    for i, event in enumerate(events, 1):
        missing_fields = sorted(required_event_fields - set(event))
        if missing_fields:
            errors.append(f"event {i} missing fields: {', '.join(missing_fields)}")
        event_id = str(event.get("event_id", ""))
        if event_id in seen_ids:
            errors.append(f"duplicate event id at line {i}: {event_id}")
        seen_ids.add(event_id)
        if event.get("event_id") != f"EV-{i:06d}":
            errors.append(f"ledger event sequence mismatch at line {i}: {event.get('event_id')}")
        # Version stamps are monotone: a ledger may start legacy (pre-7.3), but once an
        # event carries os_version, a later event missing it is a downgrade — either a
        # mixed ledger or a hand-edit that dropped the field.
        if event.get("os_version"):
            versioned_seen = True
        elif versioned_seen:
            errors.append(
                f"version stamp regression at event {i}: events after the first versioned event must carry os_version"
            )
        if event.get("type") not in EVENT_TYPES:
            errors.append(f"unknown event type at {i}: {event.get('type')}")
        if event.get("prev_hash") != prev:
            errors.append(f"ledger prev_hash mismatch at {i}")
        if event.get("event_hash") != cp._event_hash(event):
            errors.append(f"ledger event_hash mismatch at {i}")
        hits = secret_pattern_hits(json.dumps(event, ensure_ascii=False))
        if hits:
            errors.append(f"event {i} carries a secret-shaped value ({hits[0]}); redact before recording")
        prev = event.get("event_hash", "")
        if not isinstance(event.get("evidence_refs", []), list):
            errors.append(f"evidence_refs is not a list at {i}")
        else:
            for ref in event.get("evidence_refs", []):
                if not evidence_id_ok(str(ref)):
                    errors.append(f"invalid evidence ref {ref} at event {i}")
        if not isinstance(event.get("payload", {}), dict):
            errors.append(f"payload is not an object at {i}")
        causation = event.get("causation_id")
        if causation and causation not in seen_ids:
            errors.append(f"event {i} references future/unknown causation {causation}")

    # Cycle and hypothesis transition legality + projection agreement.
    for cid in cp.all_cycle_ids():
        status = None
        created = False
        for e in cp.events_for("cycle", cid):
            if e["type"] == "CYCLE_CREATED":
                if created:
                    errors.append(f"cycle {cid} has multiple CYCLE_CREATED events")
                created = True
                status = "PLANNED"
            elif e["type"] == "CYCLE_TRANSITIONED":
                to = normalize_cycle_state(e.get("payload", {}).get("to"))
                if status is None or to not in CYCLE_EDGES.get(status, set()):
                    errors.append(f"illegal cycle transition {cid}: {status} -> {to}")
                else:
                    status = to
        if not created:
            errors.append(f"cycle {cid} has no creation event")
        proj = cycle_projection_status(root, cid)
        if proj != status:
            errors.append(f"cycle {cid} projection drift: event={status} projection={proj}")
        pdata = cp.cycle_data(cid) or {}
        pdata["status"] = status
        full_proj = parse_projection(root / "04_cycles" / cid / "plan.yaml")
        if full_proj != pdata:
            errors.append(f"cycle {cid} projection content drift")
        # Knowledge triage: no cycle runs on vibes. Any cycle past READY must carry an
        # explicit per-pack USE/SKIP disposition (cheap by design; the consideration is
        # the forcing, not the context cost). Without it the agent silently underuses
        # 12_knowledge/ and current-research capabilities.
        if status not in {"PLANNED", "READY", None}:
            triage = (cp.cycle_data(cid) or {}).get("knowledge_triage")
            if not triage:
                errors.append(f"cycle {cid} past READY without knowledge_triage (pack USE/SKIP dispositions required)")

    for hid in cp.all_hypothesis_ids():
        status = None
        created = False
        for e in cp.events_for("hypothesis", hid):
            if e["type"] == "HYPOTHESIS_CREATED":
                if created:
                    errors.append(f"hypothesis {hid} has multiple HYPOTHESIS_CREATED events")
                created = True
                status = str(e.get("payload", {}).get("status", "CANDIDATE"))
            elif e["type"] == "HYPOTHESIS_TRANSITIONED":
                to = e.get("payload", {}).get("to")
                if status is None or to not in HYP_EDGES.get(status, set()):
                    errors.append(f"illegal hypothesis transition {hid}: {status} -> {to}")
                else:
                    status = to
        proj = hypothesis_projection_status(root, hid)
        if proj != status:
            errors.append(f"hypothesis {hid} projection drift: event={status} projection={proj}")
        hdata = cp.hypothesis_data(hid) or {}
        hdata["id"] = hid
        hdata["status"] = status
        archive = root / "03_hypotheses" / "archive" / f"{hid}.yaml"
        active = root / "03_hypotheses" / "active" / f"{hid}.yaml"
        expected_path = archive if status in {"CLOSED", "VERIFIED", "FALSE_POSITIVE", "NOT_APPLICABLE"} else active
        full_proj = parse_projection(expected_path)
        if full_proj != hdata:
            errors.append(f"hypothesis {hid} projection content drift")

    # Finding binding: every VERIFIED hypothesis must own its finding record.
    # Lifecycle OBSERVATION→…→VERIFIED→REPORT-DRAFT is convention; this makes the
    # VERIFIED→05_findings link machine-checked instead of honor-system.
    for hid in cp.all_hypothesis_ids():
        ev_status = None
        for e in cp.events_for("hypothesis", hid):
            if e["type"] == "HYPOTHESIS_CREATED":
                ev_status = str(e.get("payload", {}).get("status", "CANDIDATE"))
            elif e["type"] == "HYPOTHESIS_TRANSITIONED":
                ev_status = e.get("payload", {}).get("to")
        if ev_status == "VERIFIED":
            for need in ("hypothesis.md", "validation.md", "report-draft.md"):
                if not (root / "05_findings" / f"F-{hid}" / need).is_file():
                    errors.append(f"verified hypothesis {hid} lacks 05_findings/F-{hid}/{need}")

    # Surface inventory: once research has started, the endpoint ledger must exist.
    if cp.all_cycle_ids() and not (root / "02_surface" / "endpoints.yaml").is_file():
        errors.append("research started but 02_surface/endpoints.yaml is missing")

    # Evidence identity + artifact immutability, with transparent supersession:
    # a path re-registered later supersedes the earlier record (the ledger keeps
    # both; the file must match the LATEST registration). A file matching NO
    # registration is tampering and fails. Lesson encoded: register immutable
    # snapshots, never living documents — a second registration of a changed file
    # is a workflow smell, recorded as a warning, not hidden.
    index = cp.evidence_index()
    latest_by_path: dict[str, str] = {}
    for eid, meta in index.items():
        rel = str(meta.get("path", ""))
        if rel and (rel not in latest_by_path or eid > latest_by_path[rel]):
            latest_by_path[rel] = eid
    if len(index) != sum(1 for e in events if e.get("type") == "EVIDENCE_REGISTERED"):
        errors.append("evidence index contains duplicate or malformed IDs")
    for eid, meta in index.items():
        if not evidence_id_ok(eid):
            errors.append(f"invalid evidence ID: {eid}")
            continue
        rel = meta.get("path", "")
        path = (root / rel).resolve() if rel else None
        if path is None:
            errors.append(f"evidence {eid} missing path")
            continue
        try:
            path.relative_to(root)
        except ValueError:
            errors.append(f"evidence {eid} escapes engagement root")
            continue
        if not path.is_file():
            errors.append(f"evidence {eid} file missing: {rel}")
            continue
        if sha256_file(path) != meta.get("sha256"):
            if latest_by_path.get(str(rel)) != eid:
                warnings.append(f"evidence {eid} superseded by {latest_by_path.get(str(rel))}: {rel} (re-registered after change; register snapshots, not living files)")
            else:
                errors.append(f"evidence {eid} hash mismatch: {rel}")
        if path.stat().st_size != meta.get("bytes"):
            if latest_by_path.get(str(rel)) != eid:
                pass  # covered by the superseded warning above
            else:
                errors.append(f"evidence {eid} size mismatch: {rel}")
        store_rel = meta.get("store_path")
        if store_rel:
            store_path = root / str(store_rel)
            if not store_path.is_file():
                errors.append(f"evidence {eid} stored copy missing: {store_rel}")
            elif sha256_file(store_path) != meta.get("sha256"):
                errors.append(f"evidence {eid} stored copy hash mismatch: {store_rel}")
        else:
            warnings.append(f"evidence {eid} has no stored copy (legacy registration): {rel}")
        # Evidence must not carry secret-shaped values (29_SECURITY_HYGIENE: RAW -> SANITIZE
        # -> REFERENCE). Text-like files only, with a size cap so the audit stays bounded.
        if path.stat().st_size <= 1_000_000:
            try:
                blob = path.read_bytes()
                if b"\x00" not in blob:
                    hits = secret_pattern_hits(blob.decode("utf-8", errors="ignore"))
                    if hits:
                        errors.append(
                            f"evidence {eid} carries a secret-shaped value ({hits[0]}): {rel} — sanitize captures before registering"
                        )
            except OSError:
                warnings.append(f"evidence {eid} unreadable for secret scan: {rel}")

    known_refs = set(index)
    for e in events:
        for ref in e.get("evidence_refs", []):
            if ref not in known_refs:
                errors.append(f"dangling evidence ref {ref} in {e.get('event_id')}")

    # Human gate consistency; gate resolutions must not contain the secret itself.
    for gid in cp.all_gate_ids():
        gate = cp.gate(gid) or {}
        if gate.get("status") == "PENDING":
            warnings.append(f"pending human gate: {gid}")
        if gate.get("status") not in {"PENDING", "RESOLVED"}:
            errors.append(f"invalid gate status {gid}: {gate.get('status')}")
        # The word "OTP" may legitimately describe the kind of human input required.
        # Detect unredacted secret *values* only by inspecting protected field names.
        for e in cp.events_for("human_gate", gid):
            payload = e.get("payload", {})
            for key, value in payload.items() if isinstance(payload, dict) else []:
                if str(key).lower() in {"otp", "mfa", "password", "token", "secret", "private_key", "access_token", "refresh_token"} and value != "[REDACTED]":
                    errors.append(f"possible unredacted secret field {key} in gate {gid}")

    # Action preflight is a durable invariant.
    required_action = {"target", "scope_status", "account", "object_owner", "purpose", "hypothesis",
                       "expected_secure", "expected_vulnerable", "side_effect", "stop_condition"}
    for e in events:
        if e.get("type") != "ACTION_RECORDED":
            continue
        payload = e.get("payload", {})
        missing = sorted(k for k in required_action if not payload.get(k))
        if missing:
            errors.append(f"action {e.get('entity_id')} missing preflight: {', '.join(missing)}")
        elif str(payload.get("scope_status")).upper() != "IN_SCOPE":
            errors.append(f"action {e.get('entity_id')} is not IN_SCOPE")
        # Action ↔ token provenance (S5): the controlled executors record the consumed
        # preflight nonce, so an ACTION_RECORDED event links back to the token that
        # authorized it. Legacy/non-executor records warn; closure holds versioned
        # actions to it (actions_have_token_provenance).
        if not str(payload.get("token_nonce", "")).strip():
            warnings.append(
                f"action {e.get('entity_id')} carries no token_nonce (legacy or non-executor record) — "
                "controlled-executor actions carry the consumed preflight nonce"
            )

    # Scope is a live invariant: each recorded action is re-checked against the CURRENT
    # asset list, so a scope narrowed after the fact cannot stay silent. request_shape.url
    # is authoritative when present (fall back to target). Only URL/host-shaped targets
    # are re-checked: free-text labels ("the provided apk (static review, no network)")
    # describe an action, they do not name a host, and must not fail the workspace. A
    # `gate: none` opt-out or an in-scope host passes; unset/unenforceable fail closed.
    # An action whose host is listed in the previous_assets of the first SCOPE_CHANGED
    # recorded after it was in scope when recorded — downgrade to a warning instead of
    # an error.
    HOST_SHAPED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(:\d+)?$")
    scope_assets = engagement_assets(root)
    for idx, e in enumerate(events):
        if e.get("type") != "ACTION_RECORDED":
            continue
        payload = e.get("payload") or {}
        shape = payload.get("request_shape") if isinstance(payload.get("request_shape"), dict) else {}
        target = str(shape.get("url") or payload.get("target") or "").strip()
        if not target:
            continue
        if "://" not in target and not HOST_SHAPED.fullmatch(target):
            continue
        scope = scope_check(root, target if "://" in target else f"https://{target}")
        if scope["gate"] == "disabled":
            continue
        if scope["gate"] not in {"unset", "unenforceable"} and scope["in_scope"]:
            continue
        previous: list[str] = []
        for later in events[idx + 1:]:
            if later.get("type") == "SCOPE_CHANGED":
                previous = list((later.get("payload") or {}).get("previous_assets") or [])
                break
        if previous and scope["host"] and host_in_scope(scope["host"], asset_hosts(previous)):
            warnings.append(
                f"action {e.get('entity_id')} targets '{scope['host']}' which was in scope when recorded "
                "(the next SCOPE_CHANGED lists it in previous_assets) but is not in the current scope"
            )
            continue
        errors.append(
            f"action {e.get('entity_id')} targets '{scope['host']}' but the current "
            f"engagement scope does not include it (gate={scope['gate']})"
        )
    if scope_assets and not any(e.get("type") == "SCOPE_CHANGED" for e in events):
        warnings.append(
            "engagement scope has no SCOPE_CHANGED provenance record — record it via researchctl scope-set"
        )

    # Technique evaluations are the learning ledger: they are canonical events, not narrative
    # files. The projections in 10_learning/ rebuild from these; validate them here so a hand
    # edit of the ledger cannot smuggle a malformed result.
    for e in events:
        if e.get("type") != "TECHNIQUE_EVALUATED":
            continue
        payload = e.get("payload", {})
        if str(payload.get("result", "")).upper() not in TECHNIQUE_RESULTS:
            errors.append(f"technique {e.get('entity_id')} has invalid result: {payload.get('result')}")
        if not e.get("evidence_refs"):
            errors.append(f"technique {e.get('entity_id')} has no evidence refs")
        for key in ("technique_family", "interpretation", "learning"):
            if not str(payload.get(key, "")).strip():
                errors.append(f"technique {e.get('entity_id')} missing {key}")

    # Required freshness/control ledgers should exist once bootstrap has started.
    required = [
        root / "11_runtime" / "events.jsonl",
        root / "11_runtime" / "tool-registry.yaml",
        root / "11_runtime" / "lab-status.yaml",
        root / "10_learning" / "freshness.yaml",
        root / "10_learning" / "unknowns.yaml",
        root / "10_learning" / "assumptions.yaml",
    ]
    for p in required:
        if not p.exists():
            errors.append(f"required ledger/file missing: {p.relative_to(root)}")

    # Freshness watchtower (31_): the clock is mechanical — stale components are an error,
    # UNKNOWN pins stay visible as a warning (unknown is a recorded fact, not a failure).
    fresh = cp.freshness_report()
    for name in fresh["stale"]:
        errors.append(f"freshness component '{name}' is stale ({fresh['ages'].get(name)}d > max_age) — "
                      "re-run the CHECK step and record it (researchctl freshness record)")
    for name in fresh["unpinned"]:
        warnings.append(f"freshness component '{name}' is UNPINNED — pin the observed version or keep UNKNOWN deliberately")

    # Interpreter-generated .pyc files inside __pycache__ are a normal side effect of running
    # the tools themselves; flagging them made the audit FAIL on its own execution. Loose .pyc
    # files outside __pycache__ stay flagged (validate_workspace.py applies the same rule).
    junk = [p for p in root.rglob("*") if p.is_file()
            and (p.name == ".DS_Store" or (p.suffix == ".pyc" and "__pycache__" not in p.parts))]
    if junk:
        errors.append("generated/junk files present: " + ", ".join(str(p.relative_to(root)) for p in junk[:10]))

    # Secret hygiene (enforced exception model): local-only research credentials may
    # exist ONLY under lab/credentials/ with 0600, and must never be registered as
    # evidence or stored elsewhere in the workspace.
    import stat as _stat

    cred_dir = root / "lab" / "credentials"
    if cred_dir.is_dir():
        for p in sorted(cred_dir.iterdir()):
            # `.gitkeep` keeps the empty directory in the template clone; git cannot
            # carry the 0600 bit, so the placeholder is exempt. Real credential files
            # and any other file (including dotfiles) must still be 0600.
            if p.is_file() and p.name != ".gitkeep" and (p.stat().st_mode & 0o777) != 0o600:
                errors.append(f"credential file without 0600: {p.relative_to(root)}")
    stray_env = [
        p for p in root.rglob("*.env")
        if p.is_file() and cred_dir not in p.parents
        and "lab/source" not in p.relative_to(root).as_posix()
        and "node_modules" not in p.relative_to(root).as_posix()
    ]
    if stray_env:
        errors.append("credential-style file outside lab/credentials/: " + ", ".join(str(p.relative_to(root)) for p in stray_env[:5]))
    for eid, meta in index.items():
        rel = str(meta.get("path", ""))
        if rel.startswith("lab/credentials/") or "/profile-" in rel or rel.startswith("lab/browser/profile"):
            errors.append(f"evidence {eid} registers credential/session material: {rel}")

    # A resolved human gate that leaves a cycle paused is allowed only when its decision is not a resume action.
    for gid in cp.all_gate_ids():
        gate = cp.gate(gid) or {}
        cid = gate.get("cycle_id")
        if gate.get("status") == "RESOLVED" and gate.get("decision", "").upper() in {"RESUME", "PROVIDED", "APPROVED"} and cid and cp.cycle_status(str(cid)) == "HUMAN_GATE":
            errors.append(f"gate {gid} says resume but cycle {cid} remains HUMAN_GATE")
        if cid and cp.cycle_status(str(cid)) == "HUMAN_GATE" and gate.get("status") != "PENDING":
            errors.append(f"cycle {cid} is HUMAN_GATE without a pending gate")

    status = cp.refresh()
    projected_status = parse_status(root / "11_runtime" / "run-status.yaml")
    if projected_status.get("current_cycle") != (status.get("current_cycle") or "null"):
        errors.append("run-status current_cycle projection drift")
    if status.get("pending_human_gate") and not any("pending human gate" in w for w in warnings):
        warnings.append("pending human gate exists")

    # Independent challenge is protocol (11_WORKER_PROTOCOL.md: "agreement is not evidence").
    # A cycle that ever reached REVIEWED must carry passing review packets on both axes, from
    # reviewers and reviewing runs that are present and distinct, each evidence quote bound to
    # the CONTENT-ADDRESSED store copy. Versioned records are held to the full rule; legacy
    # records (pre-7.3, no os_version) keep their findings visible as warnings so archived
    # ledgers still audit cleanly.
    reviewed_cycles: set = set()
    reviews_by_cycle: dict = {}
    for e in events:
        if (e.get("type") == "CYCLE_TRANSITIONED" and e.get("cycle_id")
                and normalize_cycle_state((e.get("payload") or {}).get("to")) == "REVIEWED"):
            reviewed_cycles.add(str(e["cycle_id"]))
        if e.get("type") == "WORKER_RESULT" and e.get("cycle_id"):
            review = (e.get("payload") or {}).get("review") or {}
            axis = str(review.get("axis", "")).lower()
            if axis in {"objective", "method"}:
                reviews_by_cycle.setdefault(str(e["cycle_id"]), {})[axis] = {
                    "verdict": str(review.get("verdict", "")).lower(),
                    "reviewer": str(review.get("reviewer", "")).strip(),
                    "run_id": str(review.get("run_id", "")).strip(),
                    "evidence_refs": [str(r) for r in e.get("evidence_refs") or []],
                    "evidence_quotes": review.get("evidence_quotes"),
                    "versioned": bool(e.get("os_version")),
                }

    def grade_review(versioned: bool, message: str) -> None:
        if versioned:
            errors.append(message)
        else:
            warnings.append(f"legacy review record (pre-7.3, no os_version): {message}")

    for cid in sorted(reviewed_cycles):
        axes = reviews_by_cycle.get(cid, {})
        not_pass = [a for a in ("objective", "method") if axes.get(a, {}).get("verdict") != "pass"]
        reviewers = {a: axes.get(a, {}).get("reviewer", "") for a in ("objective", "method")}
        run_ids = {a: axes.get(a, {}).get("run_id", "") for a in ("objective", "method")}
        if not_pass:
            errors.append(f"cycle {cid} reached REVIEWED without passing reviews on: {', '.join(not_pass)}")
            continue
        if not all(reviewers.values()):
            errors.append(
                f"cycle {cid} reviews lack reviewer identity "
                f"(objective={reviewers['objective'] or 'missing'}, method={reviewers['method'] or 'missing'})"
            )
        elif reviewers["objective"] == reviewers["method"]:
            errors.append(f"cycle {cid} reviews are not independent — both axes came from '{reviewers['objective']}'")
        # Grade each axis with its OWN versioned flag: a legacy packet's absence is a
        # warning even when the sibling axis is versioned, and only a versioned packet's
        # absence is an error. One message per axis, so the remediation is unambiguous.
        for axis in ("objective", "method"):
            if not run_ids[axis]:
                grade_review(bool(axes.get(axis, {}).get("versioned")),
                             f"cycle {cid} {axis} review lacks run_id")
        if all(run_ids.values()) and run_ids["objective"] == run_ids["method"]:
            errors.append(f"cycle {cid} reviews are not independent — both axes ran in '{run_ids['objective']}'")
        for axis in ("objective", "method"):
            packet = axes.get(axis, {})
            quotes = packet.get("evidence_quotes")
            if not isinstance(quotes, list) or not quotes:
                grade_review(bool(packet.get("versioned")),
                             f"cycle {cid} {axis} review packet carries no evidence_quotes")
                continue
            for i, item in enumerate(quotes, 1):
                problem = review_quote_problem(root, index, item, i,
                                               allowed_refs=[str(r) for r in packet.get("evidence_refs") or []])
                if problem:
                    grade_review(bool(packet.get("versioned")), f"cycle {cid} {axis} {problem}")
    for cid in cp.all_cycle_ids():
        cstatus = cp.cycle_status(cid)
        if cstatus in {"REVIEWED", "CLOSED"} and cid not in reviewed_cycles and not any(
                e.get("type") == "WORKER_RESULT" and e.get("cycle_id") == cid for e in events):
            warnings.append(f"cycle {cid} reached {cstatus} with no WORKER_RESULT packet (independent challenge not evidenced)")

    # The method self-attack is only real when its six-row matrix is on the event.
    for e in events:
        if e.get("type") != "AUDIT_RECORDED" or (e.get("payload") or {}).get("class") != "method-self-attack":
            continue
        matrix = (e.get("payload") or {}).get("matrix")
        if not isinstance(matrix, dict):
            errors.append(f"method-self-attack audit {e.get('entity_id')} carries no six-row matrix")
        else:
            blank = [r for r in METHOD_SELF_ATTACK_ROWS if not str(matrix.get(r, "")).strip()]
            if blank:
                errors.append(f"method-self-attack audit {e.get('entity_id')} has blank rows: {', '.join(blank)}")

    # Audit content lite (S3): a declaration is evidence-backed and names the thing it
    # audited. Versioned records are held to the rule; legacy records warn instead.
    for e in events:
        if e.get("type") != "AUDIT_RECORDED":
            continue
        payload = e.get("payload") or {}
        cls = str(payload.get("class", e.get("entity_id") or ""))
        summary = str(payload.get("summary", "")).strip()
        problems: list[str] = []
        if not e.get("evidence_refs"):
            problems.append("carries no evidence_refs")
        if len(summary) < 20 or len(summary.split()) < 3:
            problems.append(f"has a summary too thin ({summary!r}: needs >= 20 characters and >= 3 words)")
        if cls == "scope":
            if not any(str(a) in summary for a in (scope_assets or [])) \
                    and "gate: none" not in summary and "no assets" not in summary:
                problems.append("scope summary names no current asset and neither 'gate: none' nor 'no assets'")
        elif cls == "coverage":
            if not re.search(r"C-\d+", summary) and "no cycles" not in summary:
                problems.append("coverage summary names no cycle and no 'no cycles'")
        elif cls == "open-hypothesis":
            if not re.search(r"H-\d+", summary) and not re.search(r"\bnone\b", summary, re.IGNORECASE):
                problems.append("open-hypothesis summary names no hypothesis and no 'none'")
        for problem in problems:
            if e.get("os_version"):
                errors.append(f"audit {e.get('entity_id')} ({cls}) {problem}")
            else:
                warnings.append(f"legacy audit {e.get('entity_id')} ({cls}) {problem}")

    versioned_actions_without_nonce = [
        str(e.get("entity_id")) for e in events
        if e.get("type") == "ACTION_RECORDED" and e.get("os_version")
        and not str((e.get("payload") or {}).get("token_nonce", "")).strip()
    ]

    latest_audits = latest_audit_events(events)
    last_research_event = latest_non_audit_event_id(events)
    # Steady-state forcing: once research is substantive, the core audit classes must
    # not go missing entirely. WARN (not ERROR) — closure already requires them PASS.
    if len(events) >= 30:
        for cls in ("scope", "hygiene-cleanup", "open-hypothesis", "method-self-attack"):
            if cls not in latest_audits:
                warnings.append(f"no {cls} audit recorded yet ({len(events)} events in)")
    proof_failures = closure_proof_failures(root / CLOSURE_PROOF_PATH) if closure else []
    required_audits = sorted(REQUIRED_AUDIT_CLASSES)
    closure_checks = {
        "engagement_has_cycles": bool(cp.all_cycle_ids()),
        "no_active_cycles": not any(cp.cycle_status(cid) not in {None, "CLOSED"} for cid in cp.all_cycle_ids()),
        "no_pending_human_gates": not status.get("pending_human_gate"),
        "ledger_integrity": not any("ledger" in e or "event_hash" in e for e in errors),
        "no_dangling_evidence": not any("evidence" in e.lower() and ("dangling" in e.lower() or "missing" in e.lower() or "mismatch" in e.lower()) for e in errors),
        "projections_consistent": not any("projection drift" in e for e in errors),
        "required_ledgers_present": not any("required ledger/file" in e for e in errors),
        "closure_proof_valid": not proof_failures,
        "actions_have_token_provenance": not versioned_actions_without_nonce,
    }
    for cls in required_audits:
        item = latest_audits.get(cls)
        eid = str((item or {}).get("event_id", "EV-0"))
        m = re.fullmatch(r"EV-(\d+)", eid)
        audit_seq = int(m.group(1)) if m else 0
        closure_checks[f"{cls}_audit_current"] = bool(item and item.get("status") == "PASS" and audit_seq > last_research_event)
    if closure:
        for problem in proof_failures:
            errors.append(f"closure proof: {problem}")
        if not all(closure_checks.values()):
            errors.append("closure proof failed: " + ", ".join(k for k, v in closure_checks.items() if not v))

    result = {
        "ok": not errors,
        "closure_requested": closure,
        "event_count": len(events),
        "cycles": {cid: cp.cycle_status(cid) for cid in cp.all_cycle_ids()},
        "hypotheses": {hid: cp.hypothesis_status(hid) for hid in cp.all_hypothesis_ids()},
        "evidence_count": len(index),
        "pending_gates": [gid for gid in cp.all_gate_ids() if (cp.gate(gid) or {}).get("status") == "PENDING"],
        "audit_declarations": latest_audits,
        "closure_checks": closure_checks,
        "errors": errors,
        "warnings": warnings,
    }
    return (not errors), result


def main() -> int:
    ap = argparse.ArgumentParser(prog="audit")
    ap.add_argument("root")
    ap.add_argument("--closure", action="store_true", help="also prove closure eligibility")
    ap.add_argument("--emit-proof", action="store_true",
                    help="write/refresh 06_audits/CLOSURE-PROOF.md (mechanical facts + TODO(human) prompts)")
    ap.add_argument("--force", action="store_true", help="with --emit-proof: overwrite a filled proof")
    ap.add_argument("--record-class", help="append this machine audit result to the canonical audit ledger")
    ap.add_argument("--evidence", action="append", default=[], help="registered evidence ref to attach to the audit event")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ns = ap.parse_args()
    root = Path(ns.root).resolve()
    if ns.emit_proof:
        try:
            path = emit_closure_proof(root, force=ns.force)
        except ValueError as exc:
            print(f"ERROR: {exc}")
            return 1
        if not ns.closure:
            print(f"closure proof written: {path.relative_to(root).as_posix()}")
            return 0
    ok, result = audit(root, closure=ns.closure)
    if ns.record_class:
        cp = ControlPlane(root)
        cp.record_audit(ns.record_class, "PASS" if ok else "FAIL", "machine audit completed", evidence_refs=ns.evidence)
        result["audit_recorded"] = ns.record_class
    if ns.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("PASS" if ok else "FAIL")
        for e in result["errors"]:
            print(f"ERROR: {e}")
        for w in result["warnings"]:
            print(f"WARN: {w}")
        print(f"events={result['event_count']} evidence={result['evidence_count']} pending_gates={len(result['pending_gates'])}")
        if ns.closure:
            print("closure=" + ("READY" if all(result["closure_checks"].values()) else "NOT_READY"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
