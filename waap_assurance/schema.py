import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterable

from .models import WafEvent


class InputFormatError(ValueError):
    """Raised when an input line does not match the documented WAF schema."""


class DuplicateJSONKeyError(ValueError):
    """Raised when a JSON object repeats a key and would otherwise be ambiguous."""


REQUIRED_FIELDS = {
    "event_id", "timestamp", "source_ip", "host", "method", "path",
    "status_code", "waf_action", "user_agent",
}
VALID_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
VALID_ACTIONS = {"allowed", "blocked", "challenged"}
MAX_LINE_BYTES = 1_000_000


def load_events(input_path: Path) -> list[WafEvent]:
    events: list[WafEvent] = []
    seen_ids: set[str] = set()
    with input_path.open("rb") as source:
        for line_number, raw_line in bounded_lines(source):
            if not raw_line.strip():
                continue
            try:
                decoded_line = raw_line.decode("utf-8")
            except UnicodeDecodeError as error:
                raise InputFormatError(f"line {line_number}: input must be UTF-8") from error
            event = parse_event(decoded_line, raw_line, line_number)
            store_unique_event(event, events, seen_ids, line_number)
    if not events:
        raise InputFormatError("input contains no WAF event records")
    return events


def bounded_lines(source: BinaryIO) -> Iterable[tuple[int, bytes]]:
    line_number = 0
    # Accept the exact byte limit; one extra byte detects overflow before decoding.
    while raw_line := source.readline(MAX_LINE_BYTES + 1):
        line_number += 1
        if len(raw_line) > MAX_LINE_BYTES:
            raise InputFormatError(f"line {line_number}: record exceeds {MAX_LINE_BYTES} bytes")
        yield line_number, raw_line


def parse_event(raw_line: str, raw_bytes: bytes, line_number: int) -> WafEvent:
    try:
        record = json.loads(raw_line, object_pairs_hook=unique_json_object)
    except DuplicateJSONKeyError as error:
        raise InputFormatError(f"line {line_number}: duplicate JSON field {error}") from error
    except json.JSONDecodeError as error:
        raise InputFormatError(f"line {line_number}: invalid JSON: {error.msg}") from error
    if not isinstance(record, dict):
        raise InputFormatError(f"line {line_number}: each JSONL record must be an object")
    return validate_record(record, raw_bytes, line_number)


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for key, field_value in pairs:
        if key in record:
            raise DuplicateJSONKeyError(repr(key))
        record[key] = field_value
    return record


def store_unique_event(event: WafEvent, events: list[WafEvent], seen_ids: set[str], line_number: int) -> None:
    if event.event_id in seen_ids:
        raise InputFormatError(f"line {line_number}: duplicate event_id {event.event_id!r}")
    seen_ids.add(event.event_id)
    events.append(event)


def validate_record(record: dict[str, Any], raw_bytes: bytes, line_number: int) -> WafEvent:
    missing = REQUIRED_FIELDS.difference(record)
    if missing:
        raise InputFormatError(f"line {line_number}: missing fields: {', '.join(sorted(missing))}")
    event_id = bounded_text(record["event_id"], "event_id", 128, line_number)
    host = bounded_text(record["host"], "host", 255, line_number)
    path = bounded_text(record["path"], "path", 2048, line_number)
    user_agent = bounded_optional_text(record["user_agent"], "user_agent", 512, line_number)
    timestamp = parse_timestamp(record["timestamp"], line_number)
    source_ip = parse_ip(record["source_ip"], line_number)
    method = parse_method(record["method"], line_number)
    status_code = parse_status(record["status_code"], line_number)
    action = parse_action(record["waf_action"], line_number)
    if not path.startswith("/"):
        raise InputFormatError(f"line {line_number}: path must start with '/'")
    event_hash = hashlib.sha256(raw_bytes).hexdigest()
    return WafEvent(event_id, timestamp, source_ip, host, method, path, status_code, action, user_agent, event_hash)


def bounded_text(raw_text: Any, field: str, limit: int, line_number: int) -> str:
    text = validate_text(raw_text, field, limit, line_number)
    if not text.strip():
        raise InputFormatError(f"line {line_number}: {field} cannot be empty")
    return text


def bounded_optional_text(raw_text: Any, field: str, limit: int, line_number: int) -> str:
    return validate_text(raw_text, field, limit, line_number)


def validate_text(raw_text: Any, field: str, limit: int, line_number: int) -> str:
    if not isinstance(raw_text, str) or len(raw_text) > limit:
        raise InputFormatError(f"line {line_number}: {field} must be text of at most {limit} characters")
    if any(ord(character) < 32 for character in raw_text):
        raise InputFormatError(f"line {line_number}: {field} cannot contain control characters")
    return raw_text


def parse_timestamp(raw_timestamp: Any, line_number: int) -> datetime:
    if not isinstance(raw_timestamp, str):
        raise InputFormatError(f"line {line_number}: timestamp must be an ISO 8601 string")
    try:
        timestamp_text = raw_timestamp[:-1] + "+00:00" if raw_timestamp.endswith("Z") else raw_timestamp
        parsed = datetime.fromisoformat(timestamp_text)
    except ValueError as error:
        raise InputFormatError(f"line {line_number}: timestamp is not valid ISO 8601") from error
    if parsed.tzinfo is None:
        raise InputFormatError(f"line {line_number}: timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def parse_ip(raw_ip: Any, line_number: int) -> str:
    if not isinstance(raw_ip, str):
        raise InputFormatError(f"line {line_number}: source_ip must be text")
    try:
        return str(ipaddress.ip_address(raw_ip))
    except ValueError as error:
        raise InputFormatError(f"line {line_number}: source_ip must be a valid IPv4 or IPv6 address") from error


def parse_method(raw_method: Any, line_number: int) -> str:
    method = bounded_text(raw_method, "method", 16, line_number).upper()
    if method not in VALID_METHODS:
        raise InputFormatError(f"line {line_number}: unsupported HTTP method {method!r}")
    return method


def parse_status(raw_status: Any, line_number: int) -> int:
    if isinstance(raw_status, bool) or not isinstance(raw_status, int) or not 100 <= raw_status <= 599:
        raise InputFormatError(f"line {line_number}: status_code must be an integer from 100 to 599")
    return raw_status


def parse_action(raw_action: Any, line_number: int) -> str:
    action = bounded_text(raw_action, "waf_action", 16, line_number).lower()
    if action not in VALID_ACTIONS:
        raise InputFormatError(f"line {line_number}: waf_action must be allowed, blocked, or challenged")
    return action
