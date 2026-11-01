"""Optional AI analysis abstraction; disabled by default and evidence-grounded."""

import os


class AIProvider:
	def analyze(self, evidence: list[dict]) -> dict:
		raise NotImplementedError


class DisabledProvider(AIProvider):
	def analyze(self, evidence: list[dict]) -> dict:
		return {"label": "AI-ASSISTED ANALYSIS", "status": "unavailable", "message": "AI analysis unavailable - no provider configured.", "findings": [], "supporting_evidence": []}


class LocalAIProvider(DisabledProvider):
	"""Placeholder for a configured local model; never fabricates findings."""


class OpenAIProvider(DisabledProvider):
	"""Provider slot reserved for an explicitly configured external service."""


def get_provider() -> AIProvider:
	provider = os.getenv("DF_AI_PROVIDER", "disabled").lower()
	return {"local": LocalAIProvider, "openai": OpenAIProvider}.get(provider, DisabledProvider)()