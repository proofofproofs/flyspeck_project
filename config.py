"""
Central configuration for the service and CLI tools.

- miner.py imports DEFAULT_API_BASE from here
- app.py reads configuration from environment variables; this file mirrors sensible defaults

You can either:
- set env vars before starting the processes, or
- edit these defaults and import them from your own scripts
"""

from __future__ import annotations

import os



DEFAULT_NETUID = 125
DEFAULT_API_BASE: str = os.environ.get("DEFAULT_API_BASE", os.environ.get("API_BASE", "http://86.38.238.105:8000"))




