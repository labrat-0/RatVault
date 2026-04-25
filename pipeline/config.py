"""Configuration loading and resolution for RatVault."""

import os
import sys
from pathlib import Path
from typing import Optional

import yaml
from dotenv import load_dotenv

from pipeline.models import VaultConfig


def load_config(
    cli_overrides: Optional[dict] = None,
    config_dir: Path = Path.cwd(),
) -> VaultConfig:
    """
    Load and resolve configuration with priority:
    1. CLI overrides
    2. Environment variables (RATVAULT_*)
    3. config.yaml file
    4. .env file
    5. Defaults

    Args:
        cli_overrides: Dict of CLI flags (--model, --provider, etc)
        config_dir: Directory to search for config.yaml and .env

    Returns:
        Resolved VaultConfig
    """
    cli_overrides = cli_overrides or {}
    config_data = {}

    load_dotenv(config_dir / ".env")

    config_yaml_path = config_dir / "config.yaml"
    if config_yaml_path.exists():
        try:
            with open(config_yaml_path) as f:
                yaml_data = yaml.safe_load(f) or {}
                config_data.update(yaml_data)
        except Exception as e:
            print(f"Warning: Failed to load config.yaml: {e}", file=sys.stderr)

    env_data = {
        "provider": os.getenv("RATVAULT_PROVIDER"),
        "model": os.getenv("RATVAULT_MODEL"),
        "openai_api_key": os.getenv("OPENAI_API_KEY"),
        "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
        "openrouter_api_key": os.getenv("OPENROUTER_API_KEY"),
        "ollama_base_url": os.getenv("OLLAMA_BASE_URL"),
        "output_dir": os.getenv("RATVAULT_OUTPUT_DIR"),
        "assets_dir": os.getenv("RATVAULT_ASSETS_DIR"),
    }
    config_data.update({k: v for k, v in env_data.items() if v is not None})

    config_data.update({k: v for k, v in cli_overrides.items() if v is not None})

    return VaultConfig(**config_data)


def setup_wizard(config_dir: Path = Path.cwd()) -> None:
    """
    Interactive wizard to set up configuration.

    Guides user through selecting provider and API keys,
    then writes to .env or config.yaml.
    """
    import getpass

    print("\n🔧 RatVault Configuration Wizard\n")

    provider = input(
        "Choose provider (openai/anthropic/ollama/openrouter) [ollama]: "
    ).strip()
    if not provider:
        provider = "ollama"
    if provider not in ("openai", "anthropic", "ollama", "openrouter"):
        print(f"Invalid provider: {provider}")
        return

    model = None
    api_key = None

    provider_defaults = {
        "openai": "gpt-4o-mini",
        "anthropic": "claude-3-haiku-20240307",
        "ollama": "llama3.2",
        "openrouter": "anthropic/claude-3-haiku",
    }

    model_prompt = provider_defaults.get(provider, "")
    model = input(f"Model [{model_prompt}]: ").strip() or model_prompt

    if provider != "ollama":
        api_key = getpass.getpass(f"{provider.upper()} API Key: ")

    output_method = input("Save to (env/yaml) [env]: ").strip() or "env"

    config_path = config_dir / ("config.yaml" if output_method == "yaml" else ".env")

    if output_method == "env":
        write_env(config_path, provider, model, api_key)
    else:
        write_yaml(config_path, provider, model, api_key)

    print(f"\n✅ Config saved to {config_path}")
    print(f"   Run: python ingest.py --dry-run")


def write_env(path: Path, provider: str, model: str, api_key: Optional[str]) -> None:
    """Write configuration to .env file."""
    lines = [
        f"RATVAULT_PROVIDER={provider}",
        f"RATVAULT_MODEL={model}",
    ]

    if api_key:
        if provider == "openai":
            lines.append(f"OPENAI_API_KEY={api_key}")
        elif provider == "anthropic":
            lines.append(f"ANTHROPIC_API_KEY={api_key}")
        elif provider == "openrouter":
            lines.append(f"OPENROUTER_API_KEY={api_key}")

    env_content = "\n".join(lines) + "\n"

    if path.exists():
        print(f"⚠️  {path} already exists. Overwrite? (y/n): ", end="", flush=True)
        if input().strip().lower() != "y":
            return

    path.write_text(env_content)


def write_yaml(path: Path, provider: str, model: str, api_key: Optional[str]) -> None:
    """Write configuration to config.yaml file."""
    config = {
        "provider": provider,
        "model": model,
    }

    if api_key:
        if provider == "openai":
            config["openai_api_key"] = api_key
        elif provider == "anthropic":
            config["anthropic_api_key"] = api_key
        elif provider == "openrouter":
            config["openrouter_api_key"] = api_key

    if path.exists():
        print(f"⚠️  {path} already exists. Overwrite? (y/n): ", end="", flush=True)
        if input().strip().lower() != "y":
            return

    with open(path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)
