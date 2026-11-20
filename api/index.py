"""Vercel serverless entrypoint: exposes the ShipSafe FastAPI app from src/ai_agent/main.py."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ai_agent.main import app  # noqa: E402,F401
