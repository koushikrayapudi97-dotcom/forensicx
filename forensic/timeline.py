"""Normalized filesystem event timeline."""

from forensic.filesystem import analyze


def build(path: str) -> list[dict]:
	result = analyze(path)
	events = []
	for item in result["files"]:
		for event_type in ("created", "modified", "accessed"):
			events.append({"timestamp": item[event_type], "evidence": item["relative_path"], "event": event_type.upper(), "source": "filesystem metadata"})
	return sorted(events, key=lambda event: event["timestamp"])