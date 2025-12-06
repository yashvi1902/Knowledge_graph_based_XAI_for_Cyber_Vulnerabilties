from openai import OpenAI
from backend.config import OPENROUTER_API_KEY, OPENROUTER_MODEL

_client = None

def get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(
            api_key=OPENROUTER_API_KEY,
            base_url="https://openrouter.ai/api/v1",
        )
    return _client

def call_llm(system_prompt: str, user_prompt: str, temperature: float = 0.2, max_tokens: int = 1024) -> str:
    """
    Call the LLM via OpenRouter and return the assistant message content.
    """
    client = get_client()

    resp = client.chat.completions.create(
        model=OPENROUTER_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
    )

    return resp.choices[0].message.content