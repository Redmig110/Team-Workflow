"""Bundled OpenAI registration-to-session runtime."""

from __future__ import annotations

from pathlib import Path

__version__ = "0.1.0"

PACKAGE_DIR = Path(__file__).parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent

DATA_DIR = PROJECT_ROOT / "output" / ".registrar"

TOKENS_DIR = DATA_DIR / "sessions"

CONFIG_FILE = DATA_DIR / "config.json"
