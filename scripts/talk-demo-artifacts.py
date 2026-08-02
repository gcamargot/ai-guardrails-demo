#!/usr/bin/env python3
import json
import sys
from copy import deepcopy
from pathlib import Path
from xml.etree import ElementTree

SCENARIOS = ("exploit", "meeting", "outlook", "codex")
OUTCOMES = {
    "exploit": ("insecure_effect_then_enforced_deny", 1),
    "meeting": ("exact_approval", 1),
    "outlook": ("untrusted_content_ignored", 0),
    "codex": ("server_denied", 0),
}
DETAILS = {
    "exploit": {
        "subject_kind": "external",
        "failed_condition": "smart_lock_owner_subject_required",
        "protected_effect_count": 0,
    },
    "meeting": {"proposal_state": "pending_then_approved", "approval_binding": "exact_single_use"},
    "outlook": {"content_trust": "untrusted", "derived_effect_count": 0},
    "codex": {"allowed_tool": "dev.read_repository", "smart_lock_discovered": False},
}
TOOLS = {
    "exploit": "smart_lock.unlock",
    "meeting": "calendar.submit_meeting_proposal",
    "outlook": "outlook.read_message",
    "codex": "smart_lock.unlock",
}
SCREENSHOTS = {
    "exploit": "01-exploit.svg",
    "meeting": "02-meeting.svg",
    "outlook": "03-outlook.svg",
    "codex": "04-codex.svg",
}
EFFECT_PROOF = {
    "exploit": ("insecure_effect_count=1", "protected_effect_count=0"),
    "meeting": ("event_count=1",),
    "outlook": ("derived_effect_count=0",),
    "codex": ("effect_count=0",),
}


def fail(message):
    print(f"invalid talk demo artifact: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_jsonl(source, label):
    try:
        lines = source.read_text(encoding="utf-8").splitlines() if isinstance(source, Path) else source.read().splitlines()
        records = [json.loads(line) for line in lines if line.strip()]
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid JSONL: {error}")
    if len(records) != 4:
        fail(f"{label} must contain exactly four records")
    return records


def expected_evidence(scenario, index):
    suffix = f"{index:02d}"
    return {
        "trace_id": f"fallback-{scenario}-trace-{suffix}",
        "correlation_id": f"fallback-{scenario}-correlation-{suffix}",
        "decision_id": f"fallback-{scenario}-decision-{suffix}",
        "policy_revision": "ticket-10",
    }


def validate_results(records):
    required = {"scenario", "outcome", "effect_count", "details", "mode", "verification", "evidence"}
    for index, (scenario, record) in enumerate(zip(SCENARIOS, records), start=1):
        if not isinstance(record, dict) or set(record) != required:
            fail(f"result {index} has an invalid shape")
        if record["scenario"] != scenario:
            fail(f"result {index} must be scenario {scenario}")
        outcome, effect_count = OUTCOMES[scenario]
        if record["outcome"] != outcome or type(record["effect_count"]) is not int or record["effect_count"] != effect_count:
            fail(f"result {scenario} has an invalid outcome or Effect count")
        if record["details"] != DETAILS[scenario]:
            fail(f"result {scenario} has invalid scenario details")
        if record["mode"] != "recorded" or record["verification"] != "recorded":
            fail(f"result {scenario} must be an unrendered recorded fixture")
        if record["evidence"] != expected_evidence(scenario, index):
            fail(f"result {scenario} has invalid correlation evidence")
    return records


def load_results(root):
    return validate_results(load_jsonl(root / "results.jsonl", "results"))


def render(records, mode, verification, additions=None):
    for record in records:
        rendered = deepcopy(record)
        rendered["mode"] = mode
        rendered["verification"] = verification
        if additions:
            rendered.update(additions[record["scenario"]])
        print(json.dumps(rendered, separators=(",", ":"), ensure_ascii=False))


def render_preloaded(root):
    results = load_results(root)
    responses = load_jsonl(root / "preloaded-model-responses.jsonl", "preloaded responses")
    additions = {}
    required = {"scenario", "model", "model_interpretation", "authority"}
    for scenario, response in zip(SCENARIOS, responses):
        if not isinstance(response, dict) or set(response) != required or response["scenario"] != scenario:
            fail(f"preloaded response for {scenario} has an invalid shape or order")
        interpretation = response["model_interpretation"]
        if not isinstance(response["model"], str) or not response["model"] or response["authority"] != "none":
            fail(f"preloaded response for {scenario} claims authority or lacks a model")
        if not isinstance(interpretation, dict) or interpretation.get("tool") != TOOLS[scenario] or not isinstance(interpretation.get("intent"), str):
            fail(f"preloaded response for {scenario} has an invalid Model Interpretation")
        allowed_keys = {"intent", "tool", "arguments"}
        if not set(interpretation).issubset(allowed_keys):
            fail(f"preloaded response for {scenario} contains fields outside Model Interpretation")
        additions[scenario] = {"model_response": response}
    render(results, "preloaded", "validated-preloaded-responses", additions)


def render_evidence(root):
    results = load_results(root)
    evidence_path = root / "evidence.md"
    try:
        markdown = evidence_path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"evidence Markdown is unavailable: {error}")
    positions = []
    additions = {}
    for scenario, result in zip(SCENARIOS, results):
        filename = SCREENSHOTS[scenario]
        marker = f"({filename})"
        if marker not in markdown:
            fail(f"evidence Markdown does not reference {filename}")
        positions.append(markdown.index(marker))
        path = root / filename
        try:
            svg_text = " ".join(ElementTree.parse(path).getroot().itertext())
        except (OSError, ElementTree.ParseError) as error:
            fail(f"{filename} is not valid SVG: {error}")
        for key, value in result["evidence"].items():
            if f"{key}={value}" not in svg_text:
                fail(f"{filename} does not correlate {key}")
        for proof in EFFECT_PROOF[scenario]:
            if proof not in svg_text:
                fail(f"{filename} does not prove {proof}")
        additions[scenario] = {"screenshot": filename}
    if positions != sorted(positions) or len(set(positions)) != 4:
        fail("evidence screenshots are not in scenario order")
    render(results, "evidence", "validated-screenshot-sequence", additions)


def main():
    if len(sys.argv) < 2:
        fail("missing command")
    command = sys.argv[1]
    if command == "preloaded" and len(sys.argv) == 3:
        render_preloaded(Path(sys.argv[2]))
    elif command == "evidence" and len(sys.argv) == 3:
        render_evidence(Path(sys.argv[2]))
    elif command == "recorded" and len(sys.argv) == 5:
        render(load_results(Path(sys.argv[2])), sys.argv[3], sys.argv[4])
    elif command == "contract" and len(sys.argv) == 2:
        render(validate_results(load_jsonl(sys.stdin, "smoke contract")), "live", "test-contract")
    else:
        fail("invalid command")


if __name__ == "__main__":
    main()
