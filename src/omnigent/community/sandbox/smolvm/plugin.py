"""Register the smolvm launcher with Omnigent's community provider registry."""

import os
from pathlib import Path
import re

import yaml
from omnigent.onboarding.sandboxes.registry import (
    SandboxProviderContribution,
    SandboxProviderMetadata,
)

from .config import SmolvmConfig, profile_config_model


_PROFILE_ID = re.compile(r"smolvm[-_][a-z0-9][a-z0-9_-]{0,38}\Z")
_LAUNCHER = "omnigent.community.sandbox.smolvm.launcher:SmolvmSandboxLauncher"


def _configured_profiles() -> list[str]:
    """Read only alias IDs from the explicit, pre-start server config path."""
    path = os.environ.get("OMNIGENT_CONFIG")
    if not path:
        return []
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("sandbox"), dict):
        return []
    entries = data["sandbox"].get("providers", [])
    if not isinstance(entries, list):
        return []
    profiles: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("provider")
        if isinstance(name, str) and name.startswith(("smolvm-", "smolvm_")):
            if not _PROFILE_ID.fullmatch(name):
                raise ValueError(f"invalid smolvm profile ID: {name!r}")
            if name in profiles:
                raise ValueError(f"duplicate smolvm profile ID: {name!r}")
            profiles.append(name)
    return profiles


def get_contribution() -> SandboxProviderContribution:
    """Register the base provider and each configured, stable profile ID."""
    providers = {
        "smolvm": SandboxProviderMetadata(
            name="smolvm", launcher_class=_LAUNCHER, config_model=SmolvmConfig
        ),
    }
    for name in _configured_profiles():
        providers[name] = SandboxProviderMetadata(
            name=name, launcher_class=_LAUNCHER, config_model=profile_config_model(name)
        )
    return SandboxProviderContribution(
        name="omnigent-smolvm-provider",
        providers=providers,
    )
