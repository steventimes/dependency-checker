import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


@dataclass(frozen=True, slots=True)
class EvalCase:
    case_id: str
    task: str
    should_trigger: bool
    initial_state: Mapping[str, Any]
    available_tools: tuple[str, ...]
    loaded_instructions: tuple[str, ...]
    fixtures: Mapping[str, Any]
    expected_trace_events: tuple[str, ...]
    expected_tool_calls: tuple[Mapping[str, Any], ...]
    forbidden_trace_events: tuple[str, ...]
    expected_final_status: str
    required_answer_terms: tuple[str, ...]
    forbidden_answer_terms: tuple[str, ...]
    expected_claims: Mapping[str, Any]
    quality_rubric: str
    max_tool_calls: int


@dataclass(frozen=True, slots=True)
class SuiteResult:
    passed: bool
    passed_cases: tuple[str, ...]
    failed_cases: tuple[str, ...]
    failures: Mapping[str, tuple[str, ...]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "depcheck.skill-eval-result.v2",
            "passed": self.passed,
            "passed_cases": list(self.passed_cases),
            "failed_cases": list(self.failed_cases),
            "failures": {
                case_id: list(messages)
                for case_id, messages in sorted(self.failures.items())
            },
        }


def load_cases(path: Path) -> tuple[EvalCase, ...]:
    data = _load_object(path)
    if data.get("schema") != "depcheck.skill-eval.v2":
        raise ValueError("unsupported eval case schema")
    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("eval cases must be a non-empty list")
    cases: list[EvalCase] = []
    seen: set[str] = set()
    for raw in raw_cases:
        if not isinstance(raw, dict):
            raise ValueError("each eval case must be an object")
        case_id = _required_string(raw, "case_id")
        if case_id in seen:
            raise ValueError(f"duplicate eval case: {case_id}")
        seen.add(case_id)
        should_trigger = raw.get("should_trigger")
        if not isinstance(should_trigger, bool):
            raise ValueError("should_trigger must be a boolean")
        expected_events = _string_tuple(raw, "expected_trace_events")
        forbidden_events = _string_tuple(raw, "forbidden_trace_events")
        activation_expected = "skill.activate" in expected_events
        activation_forbidden = "skill.activate" in forbidden_events
        if should_trigger != activation_expected or should_trigger == activation_forbidden:
            raise ValueError(
                f"activation contract disagrees with should_trigger: {case_id}"
            )
        budget = raw.get("cost_latency_budget")
        if not isinstance(budget, dict):
            raise ValueError("cost_latency_budget must be an object")
        max_tool_calls = budget.get("max_tool_calls")
        if not isinstance(max_tool_calls, int) or max_tool_calls < 0:
            raise ValueError("max_tool_calls must be a non-negative integer")
        _required_string(raw, "quality_rubric")
        cases.append(
            EvalCase(
                case_id=case_id,
                task=_required_string(raw, "task"),
                should_trigger=should_trigger,
                initial_state=_object(raw, "initial_state"),
                available_tools=_string_tuple(raw, "available_tools"),
                loaded_instructions=_string_tuple(raw, "loaded_instructions"),
                fixtures=_object(raw, "fixtures"),
                expected_trace_events=expected_events,
                expected_tool_calls=_tool_calls(raw, "expected_tool_calls"),
                forbidden_trace_events=forbidden_events,
                expected_final_status=_required_string(
                    raw, "expected_final_status"
                ),
                required_answer_terms=_string_tuple(
                    raw, "required_answer_terms"
                ),
                forbidden_answer_terms=_string_tuple(
                    raw, "forbidden_answer_terms"
                ),
                expected_claims=_object(raw, "expected_claims"),
                quality_rubric=_required_string(raw, "quality_rubric"),
                max_tool_calls=max_tool_calls,
            )
        )
    return tuple(cases)


def load_traces(path: Path) -> dict[str, dict[str, Any]]:
    data = _load_object(path)
    if data.get("schema") != "depcheck.skill-eval-traces.v2":
        raise ValueError("unsupported trace schema")
    traces = data.get("traces")
    if not isinstance(traces, list):
        raise ValueError("trace file must contain a traces list")
    result: dict[str, dict[str, Any]] = {}
    for trace in traces:
        if not isinstance(trace, dict):
            raise ValueError("each trace must be an object")
        case_id = _required_string(trace, "case_id")
        if case_id in result:
            raise ValueError(f"duplicate trace: {case_id}")
        result[case_id] = {
            "task": _required_string(trace, "task"),
            "initial_state": _object(trace, "initial_state"),
            "fixtures": _object(trace, "fixtures"),
            "skills_loaded": list(_string_tuple(trace, "skills_loaded")),
            "tool_calls": list(_tool_calls(trace, "tool_calls")),
            "events": list(_string_tuple(trace, "events")),
            "final_status": _required_string(trace, "final_status"),
            "final_answer": _required_string(trace, "final_answer"),
            "claims": _object(trace, "claims"),
        }
    return result


def score_suite(
    cases: Sequence[EvalCase],
    traces: Mapping[str, Mapping[str, Any]],
) -> SuiteResult:
    passed: list[str] = []
    failures: dict[str, tuple[str, ...]] = {}
    case_ids = {case.case_id for case in cases}
    for case_id in sorted(set(traces) - case_ids):
        failures[case_id] = ("trace has no matching eval case",)
    for case in cases:
        problems: list[str] = []
        trace = traces.get(case.case_id)
        if trace is None:
            problems.append("trace is missing")
        else:
            if trace.get("task") != case.task:
                problems.append("trace task does not match the eval case")
            if trace.get("initial_state") != case.initial_state:
                problems.append("trace initial_state does not match the fixture")
            if trace.get("fixtures") != case.fixtures:
                problems.append("trace fixtures do not match the eval case")
            skills_loaded = tuple(
                str(item) for item in trace.get("skills_loaded", ())
            )
            if skills_loaded != case.loaded_instructions:
                problems.append("loaded instructions do not match the eval case")
            activated = "check-dependencies" in skills_loaded
            if activated != case.should_trigger:
                problems.append("skill activation does not match should_trigger")

            raw_calls = trace.get("tool_calls", ())
            calls = tuple(
                item for item in raw_calls if isinstance(item, Mapping)
            )
            if len(calls) != len(raw_calls):
                problems.append("tool_calls must contain only objects")
            if len(calls) > case.max_tool_calls:
                problems.append(
                    f"tool-call budget exceeded: {len(calls)} > {case.max_tool_calls}"
                )
            unavailable = sorted(
                {
                    str(call.get("name", ""))
                    for call in calls
                    if str(call.get("name", "")) not in case.available_tools
                }
            )
            if unavailable:
                problems.append(
                    "unavailable tools were called: " + ", ".join(unavailable)
                )
            problems.extend(_check_tool_calls(case.expected_tool_calls, calls))

            events = (
                *(("skill.activate",) if activated else ()),
                *(f"tool.{call.get('name', '')}" for call in calls),
                *(str(item) for item in trace.get("events", ())),
            )
            if not _is_ordered_subsequence(case.expected_trace_events, events):
                problems.append("expected trace events are missing or out of order")
            forbidden = sorted(set(events) & set(case.forbidden_trace_events))
            if forbidden:
                problems.append(f"forbidden trace events: {', '.join(forbidden)}")
            if str(trace.get("final_status", "")) != case.expected_final_status:
                problems.append(
                    "final status must be " + case.expected_final_status
                )
            answer = str(trace.get("final_answer", ""))
            lowered_answer = answer.casefold()
            missing_terms = [
                term
                for term in case.required_answer_terms
                if term.casefold() not in lowered_answer
            ]
            if missing_terms:
                problems.append(
                    "answer misses rubric terms: " + ", ".join(missing_terms)
                )
            forbidden_terms = [
                term
                for term in case.forbidden_answer_terms
                if term.casefold() in lowered_answer
            ]
            if forbidden_terms:
                problems.append(
                    "answer contains forbidden claims: "
                    + ", ".join(forbidden_terms)
                )
            claims = trace.get("claims")
            if not isinstance(claims, Mapping):
                problems.append("claims must be an object")
            else:
                if not _contains(claims, case.expected_claims):
                    problems.append("claims do not match the eval case rubric")
                problems.extend(_check_claim_consistency(claims, answer))
        if problems:
            failures[case.case_id] = tuple(problems)
        else:
            passed.append(case.case_id)
    failed = tuple(sorted(failures))
    return SuiteResult(
        passed=not failed,
        passed_cases=tuple(sorted(passed)),
        failed_cases=failed,
        failures=failures,
    )


def _check_claim_consistency(
    claims: Mapping[str, Any],
    answer: str,
) -> list[str]:
    problems: list[str] = []
    security_safe = claims.get("security_safe")
    release_ready = claims.get("release_ready")
    limitations = claims.get("limitations")
    if security_safe not in {True, False, None}:
        problems.append("claims.security_safe must be boolean or null")
    if release_ready not in {True, False, None}:
        problems.append("claims.release_ready must be boolean or null")
    if not isinstance(limitations, list) or not all(
        isinstance(item, str) and item for item in limitations
    ):
        problems.append("claims.limitations must be a list of non-empty strings")

    if security_safe is not True and re.search(
        r"\b(?:dependencies?|dependency\s+set)\s+(?:is|are)\s+"
        r"(?:safe|secure)\b|\bno\s+vulnerabilities?\b",
        answer,
        re.IGNORECASE,
    ):
        problems.append("answer contradicts the structured security claim")
    if release_ready is not True and re.search(
        r"\brelease\s+(?:is\s+)?(?:approved|ready)\b|"
        r"\b(?:approved|ready|safe)\s+(?:for|to)\s+release\b",
        answer,
        re.IGNORECASE,
    ):
        problems.append("answer contradicts the structured release claim")
    return problems


def _is_ordered_subsequence(expected: Sequence[str], actual: Sequence[str]) -> bool:
    position = 0
    for event in expected:
        try:
            position = actual.index(event, position) + 1
        except ValueError:
            return False
    return True


def _check_tool_calls(
    expected: Sequence[Mapping[str, Any]],
    actual: Sequence[Mapping[str, Any]],
) -> list[str]:
    problems: list[str] = []
    position = 0
    for expected_call in expected:
        name = str(expected_call["name"])
        match = next(
            (
                (index, call)
                for index, call in enumerate(actual[position:], start=position)
                if call.get("name") == name
            ),
            None,
        )
        if match is None:
            problems.append(f"expected tool call is missing or out of order: {name}")
            continue
        index, call = match
        position = index + 1
        if call.get("arguments") != expected_call.get("arguments"):
            problems.append(f"tool arguments do not match for {name}")
        if not _contains(call.get("result"), expected_call.get("result_contains")):
            problems.append(f"tool result does not satisfy assertions for {name}")
    return problems


def _contains(actual: Any, expected: Any) -> bool:
    if isinstance(expected, Mapping):
        return isinstance(actual, Mapping) and all(
            key in actual and _contains(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return isinstance(actual, list) and all(item in actual for item in expected)
    return actual == expected


def _load_object(path: Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return data


def _required_string(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _object(data: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object")
    return dict(value)


def _tool_calls(
    data: Mapping[str, Any], key: str
) -> tuple[Mapping[str, Any], ...]:
    value = data.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list")
    calls: list[Mapping[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"{key} entries must be objects")
        _required_string(item, "name")
        _object(item, "arguments")
        if key == "tool_calls":
            _object(item, "result")
        else:
            _object(item, "result_contains")
        calls.append(dict(item))
    return tuple(calls)


def _string_tuple(data: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"{key} must be a list of non-empty strings")
    return tuple(value)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score check-dependencies traces")
    parser.add_argument("traces", type=Path)
    parser.add_argument(
        "--cases",
        type=Path,
        default=Path(__file__).with_name("cases.json"),
    )
    args = parser.parse_args(argv)
    result = score_suite(load_cases(args.cases), load_traces(args.traces))
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
