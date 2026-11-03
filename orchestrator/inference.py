"""
Vultr Serverless Inference client.

OpenAI-compatible surface at https://api.vultrinference.com/v1. Model IDs are
not hardcoded -- resolve_models() queries /models and the id comes from env,
because the catalogue changes. Ranking (rank.py) uses .client and .text_model
directly.
"""
from __future__ import annotations

import os

DEFAULT_BASE_URL = "https://api.vultrinference.com/v1"


class InferenceError(RuntimeError):
    pass


class VultrInference:
    def __init__(self, api_key: str | None = None, base_url: str | None = None,
                 text_model: str | None = None):
        self.api_key = api_key or os.environ.get("VULTR_INFERENCE_API_KEY", "")
        self.base_url = base_url or os.environ.get("VULTR_INFERENCE_BASE_URL", DEFAULT_BASE_URL)
        self.text_model = text_model or os.environ.get("FARADAY_TEXT_MODEL", "") \
            or os.environ.get("PROVEIT_TEXT_MODEL", "")
        self._client = None

    @property
    def client(self):
        if self._client is None:
            if not self.api_key:
                raise InferenceError(
                    "VULTR_INFERENCE_API_KEY is unset. Redeem the hackathon gift "
                    "code and set it in the environment.")
            from openai import OpenAI
            self._client = OpenAI(api_key=self.api_key, base_url=self.base_url)
        return self._client

    def resolve_models(self) -> list[str]:
        return [m.id for m in self.client.models.list().data]
