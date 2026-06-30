"""
LLM client with DEEPSEEK primary, DS proxy fallback.
"""

import os
import sys
import time
from typing import Optional

import httpx
from openai import OpenAI

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.config import (
    OPENAI_DS_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL,
    DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL,
)


class ModelClient:
    """LLM client with automatic fallback between backends."""

    def __init__(self):
        self.backends: list[tuple[OpenAI, str, str]] = []  # (client, model, label)

        # DEEPSEEK (primary) — direct API, reliable tool calling
        if DEEPSEEK_API_KEY:
            self.backends.append((
                OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL,
                       max_retries=2, timeout=httpx.Timeout(180.0, connect=30.0, read=180.0)),
                DEEPSEEK_MODEL, "DEEPSEEK",
            ))
        # OPENAI_DS (fallback)
        if OPENAI_DS_API_KEY and OPENAI_BASE_URL:
            self.backends.append((
                OpenAI(api_key=OPENAI_DS_API_KEY, base_url=OPENAI_BASE_URL,
                       max_retries=2, timeout=httpx.Timeout(120.0, connect=30.0, read=120.0)),
                OPENAI_MODEL, "OPENAI-DS",
            ))

        if not self.backends:
            raise RuntimeError("No LLM API key configured. Check .env file.")

        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.active_label = ""

    def call_with_tools(
        self, messages: list[dict], tools: list[dict],
        temperature: float = 0.0, max_tokens: int = 4096,
    ) -> dict:
        """Call LLM with DeepSeek native tool calling.
        Returns {"content": str, "tool_calls": list} or raises on failure.
        """
        last_error = None
        for client, model, label in self.backends:
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                msg = response.choices[0].message
                usage = response.usage
                if usage:
                    self.total_input_tokens += usage.prompt_tokens or 0
                    self.total_output_tokens += usage.completion_tokens or 0
                self.active_label = label
                return {
                    "content": msg.content or "",
                    "tool_calls": [
                        {"id": tc.id, "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                        for tc in (msg.tool_calls or [])
                    ],
                }
            except Exception as e:
                last_error = e
                print(f"  [LLM] '{label}' tool call failed: {str(e)[:100]}, switching...")
                continue
        raise last_error or RuntimeError("LLM tool call failed on all backends")

    def call(self, messages: list[dict], temperature: float = 0.0, max_tokens: int = 4096,
             max_retries: int = 3) -> str:
        """Call LLM: DS-Proxy (2 retries) → DS-Proxy-V4Pro (2 retries)."""
        last_error = None
        RETRIES_PER_BACKEND = 2

        for client, model, label in self.backends:
            for attempt in range(RETRIES_PER_BACKEND + 1):
                try:
                    response = client.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        extra_body={"thinking": {"type": "disabled"}},
                    )
                    usage = response.usage
                    if usage:
                        self.total_input_tokens += usage.prompt_tokens or 0
                        self.total_output_tokens += usage.completion_tokens or 0

                    content = response.choices[0].message.content
                    self.active_label = label
                    if content:
                        if attempt > 0:
                            print(f"  [LLM] '{label}' recovered after {attempt} retries")
                        return content
                    # Empty content: immediately switch backend (no retry)
                    print(f"  [LLM] '{label}' empty response, switching backend...")
                    break

                except Exception as e:
                    last_error = e
                    err_str = str(e)
                    is_retryable = any(x in err_str.lower() for x in ("429", "503", "rate", "overloaded", "403", "connect", "timeout", "remote_disconnect", "connection"))

                    if is_retryable and attempt < RETRIES_PER_BACKEND:
                        wait = min(2 ** attempt + 1, 15)
                        print(f"  [LLM] '{label}' {err_str[:80]} (retry {attempt+1}/{RETRIES_PER_BACKEND}), waiting {wait}s...")
                        time.sleep(wait)
                        continue
                    elif not is_retryable:
                        print(f"  [LLM] '{label}' fatal: {err_str[:100]}")
                        break  # Don't retry non-retryable errors on this backend

            # If we exhaust retries on this backend, fall through to next
            print(f"  [LLM] '{label}' exhausted, switching backend...")

        raise last_error or RuntimeError("LLM call failed on all backends")

    def get_usage(self) -> dict:
        return {
            "active_backend": self.active_label,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
        }
