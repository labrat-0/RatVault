"""Multi-LLM provider abstraction for RatVault."""

import json
import sys
import time
from typing import Optional

import httpx

from pipeline.models import LLMResponse, ProviderConfig


class LLMError(Exception):
    """Raised when an LLM call fails."""

    pass


def call_llm(
    prompt: str,
    system: str,
    config: ProviderConfig,
) -> LLMResponse:
    """
    Call an LLM with the given prompt and system message.

    Args:
        prompt: User message
        system: System prompt
        config: Provider configuration

    Returns:
        LLMResponse with content and metadata
    """
    if config.provider == "ollama":
        return _call_ollama(prompt, system, config)
    elif config.provider == "anthropic":
        return _call_anthropic(prompt, system, config)
    elif config.provider == "openai":
        return _call_openai(prompt, system, config)
    elif config.provider == "openrouter":
        return _call_openrouter(prompt, system, config)
    else:
        raise LLMError(f"Unknown provider: {config.provider}")


def call_llm_json(
    prompt: str,
    system: str,
    config: ProviderConfig,
) -> dict:
    """
    Call an LLM and parse the response as JSON.

    Args:
        prompt: User message
        system: System prompt
        config: Provider configuration

    Returns:
        Parsed JSON dict
    """
    response = call_llm(prompt, system, config)

    try:
        return json.loads(response.content)
    except json.JSONDecodeError:
        retry_prompt = prompt + "\n\nYou MUST return valid JSON only. No markdown fences."
        retry_response = call_llm(retry_prompt, system, config)
        try:
            return json.loads(retry_response.content)
        except json.JSONDecodeError as e:
            raise LLMError(f"Failed to parse JSON from {config.provider}: {e}")


def _call_ollama(
    prompt: str,
    system: str,
    config: ProviderConfig,
) -> LLMResponse:
    """Call Ollama API."""
    base_url = config.base_url or "http://localhost:11434"
    url = f"{base_url}/api/chat"

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ]

    for attempt in range(3):
        try:
            with httpx.Client(timeout=600.0) as client:
                start_time = time.time()
                response = client.post(
                    url,
                    json={
                        "model": config.model,
                        "messages": messages,
                        "stream": False,
                        "options": {"temperature": config.temperature},
                    },
                )
                duration_ms = int((time.time() - start_time) * 1000)
                response.raise_for_status()
                result = response.json()

                return LLMResponse(
                    content=result["message"]["content"],
                    model=config.model,
                    provider="ollama",
                    prompt_tokens=result.get("prompt_eval_count", 0),
                    completion_tokens=result.get("eval_count", 0),
                    duration_ms=duration_ms,
                )
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (429, 500, 502, 503) and attempt < 2:
                wait = 2 ** attempt
                print(f"Ollama error (attempt {attempt + 1}), retrying in {wait}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            raise LLMError(f"Ollama error: {e.response.status_code} {e.response.text}")
        except httpx.RequestError as e:
            raise LLMError(f"Ollama connection error: {e}")

    raise LLMError("Ollama call failed after retries")


def _call_anthropic(
    prompt: str,
    system: str,
    config: ProviderConfig,
) -> LLMResponse:
    """Call Anthropic Claude API."""
    if not config.api_key:
        raise LLMError("ANTHROPIC_API_KEY not set")

    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": config.api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    for attempt in range(3):
        try:
            with httpx.Client(timeout=300.0) as client:
                start_time = time.time()
                response = client.post(
                    url,
                    headers=headers,
                    json={
                        "model": config.model,
                        "max_tokens": config.max_tokens,
                        "system": system,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": config.temperature,
                    },
                )
                duration_ms = int((time.time() - start_time) * 1000)
                response.raise_for_status()
                result = response.json()

                return LLMResponse(
                    content=result["content"][0]["text"],
                    model=config.model,
                    provider="anthropic",
                    prompt_tokens=result.get("usage", {}).get("input_tokens", 0),
                    completion_tokens=result.get("usage", {}).get("output_tokens", 0),
                    duration_ms=duration_ms,
                )
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (429, 500, 502, 503) and attempt < 2:
                wait = 2 ** attempt
                print(f"Anthropic error (attempt {attempt + 1}), retrying in {wait}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            raise LLMError(f"Anthropic error: {e.response.status_code} {e.response.text}")
        except httpx.RequestError as e:
            raise LLMError(f"Anthropic connection error: {e}")

    raise LLMError("Anthropic call failed after retries")


def _call_openai(
    prompt: str,
    system: str,
    config: ProviderConfig,
) -> LLMResponse:
    """Call OpenAI API."""
    if not config.api_key:
        raise LLMError("OPENAI_API_KEY not set")

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }

    for attempt in range(3):
        try:
            with httpx.Client(timeout=300.0) as client:
                start_time = time.time()
                response = client.post(
                    url,
                    headers=headers,
                    json={
                        "model": config.model,
                        "max_tokens": config.max_tokens,
                        "temperature": config.temperature,
                        "system": system,
                        "messages": [{"role": "user", "content": prompt}],
                        "response_format": {"type": "json_object"},
                    },
                )
                duration_ms = int((time.time() - start_time) * 1000)
                response.raise_for_status()
                result = response.json()

                return LLMResponse(
                    content=result["choices"][0]["message"]["content"],
                    model=config.model,
                    provider="openai",
                    prompt_tokens=result.get("usage", {}).get("prompt_tokens", 0),
                    completion_tokens=result.get("usage", {}).get("completion_tokens", 0),
                    duration_ms=duration_ms,
                )
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (429, 500, 502, 503) and attempt < 2:
                wait = 2 ** attempt
                print(f"OpenAI error (attempt {attempt + 1}), retrying in {wait}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            raise LLMError(f"OpenAI error: {e.response.status_code} {e.response.text}")
        except httpx.RequestError as e:
            raise LLMError(f"OpenAI connection error: {e}")

    raise LLMError("OpenAI call failed after retries")


def _call_openrouter(
    prompt: str,
    system: str,
    config: ProviderConfig,
) -> LLMResponse:
    """Call OpenRouter API (compatible with OpenAI format)."""
    if not config.api_key:
        raise LLMError("OPENROUTER_API_KEY not set")

    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "HTTP-Referer": "https://ratvault.local",
        "X-Title": "RatVault",
        "Content-Type": "application/json",
    }

    for attempt in range(3):
        try:
            with httpx.Client(timeout=300.0) as client:
                start_time = time.time()
                response = client.post(
                    url,
                    headers=headers,
                    json={
                        "model": config.model,
                        "max_tokens": config.max_tokens,
                        "temperature": config.temperature,
                        "system": system,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
                duration_ms = int((time.time() - start_time) * 1000)
                response.raise_for_status()
                result = response.json()

                return LLMResponse(
                    content=result["choices"][0]["message"]["content"],
                    model=config.model,
                    provider="openrouter",
                    prompt_tokens=result.get("usage", {}).get("prompt_tokens", 0),
                    completion_tokens=result.get("usage", {}).get("completion_tokens", 0),
                    duration_ms=duration_ms,
                )
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (429, 500, 502, 503) and attempt < 2:
                wait = 2 ** attempt
                print(f"OpenRouter error (attempt {attempt + 1}), retrying in {wait}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            raise LLMError(f"OpenRouter error: {e.response.status_code} {e.response.text}")
        except httpx.RequestError as e:
            raise LLMError(f"OpenRouter connection error: {e}")

    raise LLMError("OpenRouter call failed after retries")
