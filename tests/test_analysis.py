from forensic.classification import classify_file
from forensic.filesystem import analyze
from forensic.metadata import extract
from forensic.search import search
from forensic.timeline import build
from forensic.ai import DisabledProvider
from forensic.adapters import tool_status
from backend.services.evidence_normalizer import format_timestamp, normalize_case


def test_filesystem_analysis_and_classification(tmp_path):
	text = tmp_path / "notes.txt"
	text.write_text("TEST DATA keyword alpha", encoding="utf-8")
	assert classify_file(text)["category"] == "Document"
	result = analyze(tmp_path)
	assert result["status"] == "supported"
	assert result["files"][0]["relative_path"] == "notes.txt"
	assert build(str(tmp_path))[0]["source"] == "filesystem metadata"


def test_search_and_metadata_are_truthful(tmp_path):
	text = tmp_path / "notes.txt"
	text.write_text("phone@example.test", encoding="utf-8")
	results = search(str(tmp_path), "example")
	assert results[0]["location"] == 1
	metadata = extract(text)
	assert metadata["status"] == "metadata present"
	assert metadata["filename"] == "notes.txt"


def test_image_filesystem_is_explicitly_unsupported(tmp_path):
	image = tmp_path / "authorized.img"
	image.write_bytes(b"TEST DATA")
	result = analyze(image)
	assert result["message"] == "Unsupported filesystem"


def test_ai_and_external_adapters_are_truthful_by_default():
	result = DisabledProvider().analyze([])
	assert result["label"] == "AI-ASSISTED ANALYSIS"
	assert result["findings"] == []
	assert "no provider configured" in result["message"]
	assert all("Commercial forensic source not configured." in item["status"] for item in tool_status())


def test_android_normalization_maps_types_and_milliseconds(tmp_path):
	case_id = "CASE-NORMALIZED"
	path = tmp_path / case_id / "acquired"
	path.mkdir(parents=True)
	(path / "mobile_intelligence.json").write_text('{"sms":{"records":[{"_id":"71","address":"AX-ADHAAR","date":"1722578066893","type":"1","body":"నమస్తే"}]},"call_logs":{"records":[{"_id":"1","number":"123","date":"1722578066893","duration":"125","type":"3","name":"Unknown"}]}}', encoding="utf-8")
	result = normalize_case({"case_id": case_id, "case_name": "Test"}, tmp_path)
	assert result["summary"]["messages"] == 1
	assert result["messages"][0]["type"] == "Incoming"
	assert result["messages"][0]["body"] == "నమస్తే"
	assert result["calls"][0]["type"] == "Missed"
	assert result["calls"][0]["duration"] == "02:05"
	assert format_timestamp("1722578066893") != "1722578066893"