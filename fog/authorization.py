"""MEMBER 2: Phase 3 policy authorization."""

import json
from pathlib import Path


POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "policies.json"


def load_policies() -> dict:
    with POLICY_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def authorize(device_type: str, resource: str, operation: str, provisional: bool) -> bool:
    mode = "provisional" if provisional else "permanent"
    rules = load_policies().get(mode, {}).get(device_type, {})
    return operation.upper() in [item.upper() for item in rules.get(resource, [])]

