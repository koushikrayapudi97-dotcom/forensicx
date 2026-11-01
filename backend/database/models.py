"""Validated request models for public API input."""

from pydantic import BaseModel, Field

from backend.config import IDENTIFIER_REGEX, SERIAL_REGEX


class CaseCreate(BaseModel):
	case_name: str = Field(min_length=1, max_length=200)
	investigator: str = Field(min_length=1, max_length=120)
	description: str = Field(default="", max_length=5000)
	organization: str = Field(default="", max_length=200)


class EvidenceCreate(BaseModel):
	case_id: str = Field(min_length=1, max_length=80, pattern=IDENTIFIER_REGEX)
	device_serial: str = Field(min_length=1, max_length=200, pattern=SERIAL_REGEX)
	evidence_type: str = Field(min_length=1, max_length=120)
	source: str = Field(min_length=1, max_length=500)
	file_path: str = Field(min_length=1, max_length=1000)


class CustodyCreate(BaseModel):
	evidence_id: str = Field(min_length=1, max_length=80, pattern=IDENTIFIER_REGEX)
	action: str = Field(min_length=1, max_length=40)
	person: str = Field(min_length=1, max_length=120)
	description: str = Field(min_length=1, max_length=2000)


class AcquisitionCreate(BaseModel):
	case_id: str = Field(min_length=1, max_length=80, pattern=IDENTIFIER_REGEX)
	serial: str = Field(min_length=1, max_length=200, pattern=SERIAL_REGEX)
	source: str = Field(default="adb", min_length=1, max_length=80)
	method: str = Field(default="ADB / Logical Acquisition", min_length=1, max_length=160)


class ImageImportCreate(BaseModel):
	case_id: str = Field(min_length=1, max_length=80, pattern=IDENTIFIER_REGEX)
	source_path: str = Field(min_length=1, max_length=2000)
	investigator: str = Field(min_length=1, max_length=120)
	device_id: str | None = Field(default=None, max_length=80, pattern=IDENTIFIER_REGEX)
	acquisition_id: str | None = Field(default=None, max_length=80, pattern=IDENTIFIER_REGEX)


class AuthorizedImportCreate(BaseModel):
	case_id: str = Field(min_length=1, max_length=80, pattern=IDENTIFIER_REGEX)
	source_path: str = Field(min_length=1, max_length=4000)
	investigator: str = Field(min_length=1, max_length=120)
	source: str = Field(min_length=1, max_length=200)
	evidence_type: str = Field(min_length=1, max_length=120)
	device_id: str | None = Field(default=None, max_length=80, pattern=IDENTIFIER_REGEX)
	acquisition_id: str | None = Field(default=None, max_length=80, pattern=IDENTIFIER_REGEX)