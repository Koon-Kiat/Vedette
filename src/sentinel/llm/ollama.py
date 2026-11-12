"""Minimal client for the local Ollama chat API.

Sends a system message, a user message and a JSON schema in ``format``. It
never sends tools, so the model has nothing to call. Verified on Ollama
0.40.16 with qwen3:8b: the schema constraint holds with ``think`` off and on.
"""

from typing import Any

import httpx


class OllamaUnavailable(Exception):
    """Ollama could not be reached or did not return a chat message."""


class OllamaClient:
    """Talks to one Ollama server with one model."""

    def __init__(
        self,
        base_url: str,
        *,
        model: str,
        think: bool,
        temperature: float,
        num_ctx: int,
        keep_alive: str,
        timeout_seconds: float = 300.0,
    ) -> None:
        """Create a client.

        Args:
            base_url: Ollama's address on the internal network.
            model: Model tag, for example ``qwen3:8b``.
            think: Whether to let a reasoning model think before answering.
            temperature: Sampling temperature.
            num_ctx: Context window in tokens.
            keep_alive: How long Ollama keeps the model loaded after a call.
            timeout_seconds: Longest wait for one answer (covers model loading).
        """
        self._model = model
        self._think = think
        self._options = {"temperature": temperature, "num_ctx": num_ctx}
        self._keep_alive = keep_alive
        self._client = httpx.AsyncClient(
            base_url=base_url, timeout=httpx.Timeout(timeout_seconds, connect=10.0)
        )

    @property
    def model(self) -> str:
        """The model tag in use."""
        return self._model

    async def aclose(self) -> None:
        """Close the underlying HTTP connections."""
        await self._client.aclose()

    async def chat_json(self, system: str, user: str, schema: dict[str, Any]) -> str:
        """Ask the model for an answer constrained to ``schema``; return its text.

        The text is returned as-is and must still be validated by the caller.

        Raises:
            OllamaUnavailable: Network failure, timeout, an error status (for
                example the model is not downloaded), or a malformed reply.
        """
        body = {
            "model": self._model,
            "stream": False,
            "think": self._think,
            "format": schema,
            "keep_alive": self._keep_alive,
            "options": self._options,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            response = await self._client.post("/api/chat", json=body)
        except httpx.HTTPError as exc:
            raise OllamaUnavailable(type(exc).__name__) from exc
        if response.status_code != 200:
            raise OllamaUnavailable(f"HTTP {response.status_code}")
        try:
            content = response.json()["message"]["content"]
        except ValueError, KeyError, TypeError:
            raise OllamaUnavailable("reply was not a chat message") from None
        if not isinstance(content, str):
            raise OllamaUnavailable("reply was not a chat message")
        return content
