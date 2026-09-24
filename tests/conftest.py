"""Test-wide guards — keep tests offline and deterministic."""

import os

# Never hit the real JEV/OpenRouter API from tests, even if the developer's .env enables it.
os.environ["JEV_ENABLED"] = "false"
