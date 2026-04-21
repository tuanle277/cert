"""Model backends: mock, hf (HuggingFace/GPU), gemini, api (OpenAI), ollama."""

import os
from typing import Any

def _load_dotenv() -> None:
    """Load .env from cwd or project root (best-effort)."""
    candidates = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env"),
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", ".env"),
    ]
    for p in candidates:
        p = os.path.normpath(p)
        if os.path.isfile(p):
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip())
            break

_load_dotenv()


def generate(
    prompt: str,
    mode: str = "mock",
    model_name: str | None = None,
    temperature: float = 0.2,
    seed: int | None = None,
    system: str | None = None,
    api_base: str | None = None,
) -> str:
    """Generate one completion. Returns raw string.

    Modes: mock | hf (HuggingFace GPU) | gemini | api | ollama
    """
    mode = (mode or "mock").lower().strip()
    if mode == "mock":
        return "[mock] completed."

    if mode == "hf":
        return _generate_hf(
            prompt=prompt,
            model_name=model_name or "Qwen/Qwen2.5-3B-Instruct",
            temperature=temperature,
            system=system,
        )

    if mode == "gemini":
        return _generate_gemini(
            prompt=prompt,
            model_name=model_name or os.environ.get("GEMINI_MODEL", "gemini-2.0-flash"),
            temperature=temperature,
            system=system,
        )

    if mode == "api":
        return _generate_api(
            prompt=prompt,
            model_name=model_name or os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            temperature=temperature,
            seed=seed,
            system=system,
            api_base=api_base,
        )

    if mode == "ollama" or mode == "oss_llm":
        return _generate_ollama(
            prompt=prompt,
            model_name=model_name or os.environ.get("OLLAMA_MODEL", "llama3.2"),
            temperature=temperature,
            system=system,
        )

    return "[mock] completed."


_HF_MODEL_CACHE: dict[str, Any] = {}


def _generate_hf(
    prompt: str,
    model_name: str,
    temperature: float = 0.2,
    system: str | None = None,
) -> str:
    """Generate using HuggingFace transformers on GPU (or CPU fallback).

    Supports 4-bit quantization via bitsandbytes when the env var
    HF_LOAD_IN_4BIT=1 is set (useful for >=14B models on 24GB GPUs).
    """
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError:
        return "[error] pip install torch transformers"

    if model_name not in _HF_MODEL_CACHE:
        print(f"[hf] Loading {model_name} ...")
        tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
        device = "cuda" if torch.cuda.is_available() else "cpu"
        use_4bit = os.environ.get("HF_LOAD_IN_4BIT", "0") == "1"

        load_kwargs: dict[str, Any] = {"trust_remote_code": True}
        if use_4bit and device == "cuda":
            try:
                from transformers import BitsAndBytesConfig
                load_kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_quant_type="nf4",
                )
                load_kwargs["device_map"] = "auto"
                print(f"[hf] Using 4-bit quantization (nf4)")
            except ImportError:
                print("[hf] bitsandbytes not installed, falling back to FP16")
                load_kwargs["torch_dtype"] = torch.float16
                load_kwargs["device_map"] = "auto"
        elif device == "cuda":
            load_kwargs["torch_dtype"] = torch.float16
            load_kwargs["device_map"] = "auto"
        else:
            load_kwargs["torch_dtype"] = torch.float32

        model = AutoModelForCausalLM.from_pretrained(model_name, **load_kwargs)
        if device == "cpu":
            model = model.to(device)
        model.eval()
        _HF_MODEL_CACHE[model_name] = (model, tokenizer, device)
        mem_used = torch.cuda.memory_allocated() / 1e9 if device == "cuda" else 0
        print(f"[hf] Loaded on {device}" + (f" ({mem_used:.1f} GB VRAM)" if mem_used else ""))

    model, tokenizer, device = _HF_MODEL_CACHE[model_name]
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    try:
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    except Exception:
        text = (system + "\n\n" if system else "") + prompt

    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=4096)
    inputs = {k: v.to(model.device) for k, v in inputs.items()}

    import torch
    with torch.no_grad():
        gen_kwargs: dict[str, Any] = {"max_new_tokens": 512, "do_sample": temperature > 0}
        if temperature > 0:
            gen_kwargs["temperature"] = temperature
            gen_kwargs["top_p"] = 0.9
        outputs = model.generate(**inputs, **gen_kwargs)

    new_tokens = outputs[0][inputs["input_ids"].shape[1]:]
    return tokenizer.decode(new_tokens, skip_special_tokens=True).strip()


def _generate_gemini(
    prompt: str,
    model_name: str,
    temperature: float = 0.2,
    system: str | None = None,
) -> str:
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        return "[error] install google-genai: pip install google-genai"

    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        return "[error] set GEMINI_API_KEY env var"

    client = genai.Client(api_key=api_key)
    config = types.GenerateContentConfig(temperature=temperature)
    if system:
        config.system_instruction = system

    import time
    max_retries = 5
    for attempt in range(max_retries):
        try:
            resp = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=config,
            )
            return (resp.text or "").strip()
        except Exception as e:
            err = str(e)
            if "429" in err or "RESOURCE_EXHAUSTED" in err:
                wait = min(2 ** attempt * 5, 60)
                print(f"[gemini] rate limited, retrying in {wait}s (attempt {attempt+1}/{max_retries})")
                time.sleep(wait)
                continue
            return f"[error] gemini: {e}"
    return "[error] gemini: rate limit exceeded after retries"


def _generate_api(
    prompt: str,
    model_name: str,
    temperature: float = 0.2,
    seed: int | None = None,
    system: str | None = None,
    api_base: str | None = None,
) -> str:
    try:
        from openai import OpenAI
    except ImportError:
        return "[mock] completed. (install openai for mode=api)"

    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"), base_url=api_base or os.environ.get("OPENAI_BASE_URL"))
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    kwargs: dict[str, Any] = {"model": model_name, "messages": messages, "temperature": temperature}
    if seed is not None:
        kwargs["seed"] = seed
    resp = client.chat.completions.create(**kwargs)
    choice = resp.choices[0] if resp.choices else None
    if not choice or not getattr(choice, "message", None):
        return "[mock] completed."
    return (choice.message.content or "").strip()


def _generate_ollama(prompt: str, model_name: str, temperature: float = 0.2, system: str | None = None) -> str:
    try:
        import urllib.request
        import json
    except ImportError:
        return "[mock] completed."

    url = os.environ.get("OLLAMA_HOST", "http://localhost:11434") + "/api/generate"
    body = {
        "model": model_name,
        "prompt": (system + "\n\n" + prompt) if system else prompt,
        "stream": False,
        "options": {"temperature": temperature},
    }
    try:
        req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read().decode())
        return (data.get("response") or "").strip()
    except Exception as e:
        print(f"[ollama] ERROR: {e}")
        return f"[error] ollama unreachable: {e}"


def get_model_info(mode: str, model_name: str | None = None) -> str:
    """Short description for logs (no secrets)."""
    if (mode or "mock").lower() == "mock":
        return "mock"
    name = model_name or ""
    if (mode or "").lower() == "hf":
        return f"hf:{name or 'Qwen/Qwen2.5-3B-Instruct'}"
    if (mode or "").lower() == "gemini":
        return f"gemini:{name or os.environ.get('GEMINI_MODEL', 'gemini-2.0-flash')}"
    if (mode or "").lower() == "api":
        return f"api:{name or os.environ.get('OPENAI_MODEL', '?')}"
    if (mode or "").lower() in ("ollama", "oss_llm"):
        return f"ollama:{name or os.environ.get('OLLAMA_MODEL', '?')}"
    return mode or "mock"
