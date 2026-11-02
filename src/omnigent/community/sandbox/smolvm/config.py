"""Operator-authored configuration for a managed smolvm sandbox."""

import ipaddress
import re
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, create_model, field_validator, model_validator


_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
#: A bare hostname or an IP literal, never a URL, a port, or a shell fragment.
_HOSTNAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
#: ``--allow-host-pattern`` accepts an exact name or a single leading ``*.``.
_HOST_PATTERN = re.compile(r"(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
#: ``HOST[-END]:GUEST[-END]`` with an optional ``/udp``; ranges are one-to-one.
_PORT_MAP = re.compile(r"(\d{1,5})(?:-(\d{1,5}))?:(\d{1,5})(?:-(\d{1,5}))?(?:/udp)?\Z")
#: smolvm refuses more than 64 concrete host-to-guest mappings per machine.
MAX_PORT_MAPPINGS = 64


def _network(value: str, field: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse *value* as a CIDR, rejecting anything a shell could reinterpret."""
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError(f"{field} entry must be an IP address or CIDR: {value!r}") from None


class BindMount(BaseModel):
    """One host directory exposed inside the guest.

    smolvm mounts directories only; a single file is rejected at prepare time
    rather than silently creating a directory in its place. ``staged`` runs the
    workload from a guest-local copy seeded at first boot, which suits
    metadata-heavy trees and is mirrored back by ``machine sync``.
    """

    model_config = ConfigDict(extra="forbid")

    source: Path
    target: str
    mode: Literal["ro", "rw", "staged"] = "ro"
    per_session: bool = False

    @field_validator("source")
    @classmethod
    def validate_source(cls, path: Path) -> Path:
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("mount source must be an absolute path without '..'")
        if any(character in str(path) for character in ":\r\n\x00"):
            raise ValueError("mount source cannot contain colon or control characters")
        return path

    @field_validator("target")
    @classmethod
    def validate_target(cls, target: str) -> str:
        path = PurePosixPath(target)
        if not path.is_absolute() or target == "/" or ".." in target.split("/"):
            raise ValueError("mount target must be an absolute directory without '..'")
        if any(character in target for character in ":\r\n\x00"):
            raise ValueError("mount target cannot contain colon or control characters")
        return target

    @model_validator(mode="after")
    def validate_session_mount(self) -> "BindMount":
        if self.per_session and self.mode == "ro":
            raise ValueError("per-session mounts must be writable")
        return self


class KeyringKey(BaseModel):
    """Map a host keyring credential to a guest process variable.

    Three lookup shapes, most specific first:

    - ``keyring`` + ``description`` — an item whose label is ``description``
      inside the Secret Service collection named ``keyring``.
    - ``item_label`` — an item label in the default collection (legacy form).
    - ``key_name`` + ``service`` — the ``keyring`` module's service/account
      lookup, the most portable shape.

    The value is resolved on the host for each exec and handed to smolvm as a
    ``--secret-env`` reference, so it never reaches argv, the machine record,
    or an error message.
    """

    model_config = ConfigDict(extra="forbid")

    key_name: str | None = Field(default=None, min_length=1)
    env_var: str
    service: str = Field(default="omnigent-smolvm-provider", min_length=1)
    item_label: str | None = Field(default=None, min_length=1)
    keyring: str | None = Field(default=None, min_length=1)
    description: str | None = Field(default=None, min_length=1)

    @field_validator("env_var")
    @classmethod
    def validate_env_var(cls, name: str) -> str:
        if not _ENV_NAME.fullmatch(name):
            raise ValueError("env_var must be an environment variable name")
        return name

    @model_validator(mode="after")
    def validate_lookup(self) -> "KeyringKey":
        if self.keyring is not None and self.description is None:
            raise ValueError("keyring requires a description (the item label)")
        if self.key_name is None and self.item_label is None and self.description is None:
            raise ValueError("one of key_name, item_label, or description is required")
        return self


class CredentialBinding(BaseModel):
    """A gateway-brokered credential the guest may use but never read.

    ``hosts`` are the only destinations a substituted value is released to.
    smolvm injects it into an HTTPS request header and refuses it anywhere else.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    env_var: str
    hosts: list[str] = Field(min_length=1)
    set_header: str | None = None

    @field_validator("name", "env_var")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
            raise ValueError("credential names cannot contain '=', '@', or whitespace")
        return value

    @field_validator("hosts")
    @classmethod
    def validate_hosts(cls, hosts: list[str]) -> list[str]:
        invalid = [host for host in hosts if not _HOSTNAME.fullmatch(host)]
        if invalid:
            raise ValueError(f"credential hosts must be bare hostnames: {invalid}")
        return hosts

    @field_validator("set_header")
    @classmethod
    def validate_header(cls, header: str | None) -> str | None:
        if header is not None and not re.fullmatch(r"[A-Za-z0-9-]+", header):
            raise ValueError("set_header must be a plain HTTP header name")
        return header

    def render(self) -> str:
        """Render the ``--credential`` value smolvm expects."""
        spec = f"{self.name}={self.env_var}@{','.join(self.hosts)}"
        if self.set_header is not None:
            spec += f":set-header={self.set_header}"
        return spec


class SmolvmConfig(BaseModel):
    """Image, resources, mounts, and the policy enforced outside the guest."""

    model_config = ConfigDict(extra="forbid")

    image: str = Field(min_length=1)
    provider_id: Literal["smolvm"] = Field(default="smolvm", exclude=True)
    binary: str = Field(default="smolvm", min_length=1)

    cpus: int = Field(default=4, ge=1, le=64)
    memory_mib: int = Field(default=8192, ge=256, le=1_048_576)
    storage_gb: int | None = Field(default=None, ge=1, le=4096)
    overlay_gb: int | None = Field(default=None, ge=1, le=4096)

    net: bool = True
    net_backend: Literal["tsi", "virtio-net"] | None = None
    #: Hostnames resolved at machine start. The tightest egress control smolvm
    #: offers: anything not listed here (and not covered by a CIDR grant) has no
    #: route out of the guest.
    allow_hosts: list[str] = Field(default_factory=list)
    allow_host_patterns: list[str] = Field(default_factory=list)
    allow_cidrs: list[str] = Field(default_factory=list)
    deny_cidrs: list[str] = Field(default_factory=list)
    #: Re-open one otherwise-blocked range under ``block_private``. The managed
    #: host reaches the Omnigent server through the guest gateway, which lives
    #: in CGNAT space, so a fenced profile must re-open that subnet.
    allow_private: list[str] = Field(default_factory=list)
    #: Pin the guest link subnet. Its first address is the gateway, which is
    #: where the guest reaches host loopback; the second is the guest itself.
    guest_subnet: str | None = None
    #: Close the LAN, cloud metadata, CGNAT, and the host's loopback while the
    #: public internet stays open.
    block_private: bool = False
    outbound_localhost_only: bool = False
    credentials: list[CredentialBinding] = Field(default_factory=list)

    #: Host-to-guest TCP/UDP mappings, fixed at create time. A guest-side relay
    #: can move a container's port onto one of these slots, so this is a pool of
    #: concurrently reachable ports, not a limit on what the agent may serve.
    ports: list[str] = Field(default_factory=list)

    env: list[str] = Field(default_factory=list)
    environment: dict[str, str] = Field(default_factory=dict)
    mounts: list[BindMount] = Field(default_factory=list)
    keys: list[KeyringKey] = Field(default_factory=list)
    ssh_agent: bool = False
    user: str | None = None
    workdir: str | None = None
    init: list[str] = Field(default_factory=list)
    bootstrap_command: str | None = Field(default=None, min_length=1)
    startup_timeout_s: int = Field(default=180, ge=1, le=3600)

    #: Give each sandbox its own host directory, mounted at
    #: ``agent_workspace_target``, so concurrent sandboxes never share scratch
    #: work. The directory is named after the session and outlives the machine.
    agent_workspace: bool = False
    agent_workspace_root: Path | None = None
    agent_workspace_target: str | None = None
    runtime_home: str = Field(default="/root", min_length=2)

    #: Keep each machine's smolvm state (machines, images, caches) under its own
    #: directory. Isolation is stronger but every sandbox re-pulls the image;
    #: the default shares one store and relies on unique machine names.
    state_dir_root: Path | None = None

    @field_validator("image", "binary")
    @classmethod
    def validate_token(cls, value: str) -> str:
        """Reject anything that would be read as an option by the CLI."""
        if value.startswith("-") or any(character in value for character in "\x00\r\n"):
            raise ValueError("value cannot start with '-' or contain control characters")
        return value

    @field_validator("allow_hosts")
    @classmethod
    def validate_allow_hosts(cls, hosts: list[str]) -> list[str]:
        if len(hosts) != len(set(hosts)):
            raise ValueError("allow_hosts must be unique")
        invalid = [host for host in hosts if not _HOSTNAME.fullmatch(host)]
        if invalid:
            raise ValueError(f"allow_hosts entries must be bare hostnames: {invalid}")
        return hosts

    @field_validator("allow_host_patterns")
    @classmethod
    def validate_allow_host_patterns(cls, patterns: list[str]) -> list[str]:
        if len(patterns) != len(set(patterns)):
            raise ValueError("allow_host_patterns must be unique")
        invalid = [pattern for pattern in patterns if not _HOST_PATTERN.fullmatch(pattern)]
        if invalid:
            raise ValueError(
                f"allow_host_patterns entries must be a hostname or '*.domain': {invalid}"
            )
        return patterns

    @field_validator("allow_cidrs", "deny_cidrs", "allow_private")
    @classmethod
    def validate_cidrs(cls, cidrs: list[str]) -> list[str]:
        if len(cidrs) != len(set(cidrs)):
            raise ValueError("CIDR entries must be unique")
        for cidr in cidrs:
            if "/" not in cidr:
                raise ValueError(f"CIDR entry needs an explicit prefix length: {cidr!r}")
            _network(cidr, "CIDR")
        return cidrs

    @field_validator("guest_subnet")
    @classmethod
    def validate_guest_subnet(cls, subnet: str | None) -> str | None:
        """Require a small IPv4 link subnet the gateway and guest can share."""
        if subnet is None:
            return None
        network = ipaddress.ip_network(subnet, strict=True) if "/" in subnet else None
        if network is None or not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("guest_subnet must be an IPv4 CIDR, e.g. 100.96.0.0/30")
        if not 8 <= network.prefixlen <= 30:
            raise ValueError(
                "guest_subnet must be between /8 and /30 (gateway plus guest)"
            )
        return subnet

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports: list[str]) -> list[str]:
        """Check the mapping grammar and that ranges are one-to-one."""
        if len(ports) != len(set(ports)):
            raise ValueError("ports must be unique")
        total = 0
        for mapping in ports:
            match = _PORT_MAP.fullmatch(mapping)
            if match is None:
                raise ValueError(
                    f"port mapping must be HOST[-END]:GUEST[-END][/udp], got {mapping!r}"
                )
            host_start = int(match.group(1))
            host_end = int(match.group(2) or host_start)
            guest_start = int(match.group(3))
            guest_end = int(match.group(4) or guest_start)
            for port in (host_start, host_end, guest_start, guest_end):
                if not 1 <= port <= 65535:
                    raise ValueError(f"port mapping {mapping!r} has an out-of-range port")
            if host_end < host_start or guest_end < guest_start:
                raise ValueError(f"port mapping {mapping!r} has a descending range")
            if host_end - host_start != guest_end - guest_start:
                raise ValueError(
                    f"port mapping {mapping!r} must map ranges one-to-one "
                    "(the same number of host and guest ports)"
                )
            total += host_end - host_start + 1
        if total > MAX_PORT_MAPPINGS:
            raise ValueError(
                f"ports declare {total} concrete mappings; smolvm allows {MAX_PORT_MAPPINGS}"
            )
        return ports

    @field_validator("env")
    @classmethod
    def validate_env(cls, names: list[str]) -> list[str]:
        """Only variable names belong in config; values stay in the server env."""
        if len(names) != len(set(names)) or any(not _ENV_NAME.fullmatch(name) for name in names):
            raise ValueError("env must contain unique environment variable names")
        return names

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, values: dict[str, str]) -> dict[str, str]:
        for name, value in values.items():
            if not _ENV_NAME.fullmatch(name):
                raise ValueError(f"environment key is not an env var name: {name!r}")
            if "\x00" in value or "\n" in value:
                raise ValueError(f"environment {name!r} value cannot contain NUL or newline")
        return values

    @field_validator("init")
    @classmethod
    def validate_init(cls, commands: list[str]) -> list[str]:
        for command in commands:
            if not command.strip() or "\x00" in command:
                raise ValueError("init commands must be non-empty and free of NUL")
        return commands

    @field_validator("workdir", "runtime_home")
    @classmethod
    def validate_guest_path(cls, path: str) -> str:
        if not path.startswith("/") or ".." in path.split("/"):
            raise ValueError("guest paths must be absolute without '..'")
        return path

    @field_validator("user")
    @classmethod
    def validate_user(cls, name: str | None) -> str | None:
        if name is not None and not re.fullmatch(r"[A-Za-z0-9_.-]+(?::[0-9]+)?", name):
            raise ValueError("user must be a name or uid[:gid]")
        return name

    @field_validator("mounts")
    @classmethod
    def validate_mount_targets(cls, mounts: list[BindMount]) -> list[BindMount]:
        targets = [PurePosixPath(mount.target) for mount in mounts]
        if any(
            left == right or left in right.parents or right in left.parents
            for index, left in enumerate(targets)
            for right in targets[index + 1 :]
        ):
            raise ValueError("mount targets must be distinct and non-overlapping")
        return mounts

    @model_validator(mode="after")
    def validate_keys(self) -> "SmolvmConfig":
        names = [key.env_var for key in self.keys]
        if len(names) != len(set(names)):
            raise ValueError("keyring env_var names must be unique")
        if set(names) & set(self.env) or set(names) & set(self.environment):
            raise ValueError("keyring env_var names cannot also appear in env or environment")
        brokered = [binding.env_var for binding in self.credentials]
        if set(brokered) & set(names):
            raise ValueError("a credential env_var cannot also be a keyring env_var")
        return self

    @model_validator(mode="after")
    def validate_agent_workspace(self) -> "SmolvmConfig":
        if not self.agent_workspace:
            if (
                self.agent_workspace_root is not None
                or self.agent_workspace_target is not None
            ):
                raise ValueError(
                    "agent_workspace_root and agent_workspace_target require agent_workspace: true"
                )
            return self
        root = self.agent_workspace_root
        if root is None:
            raise ValueError("agent_workspace: true requires agent_workspace_root")
        if not root.is_absolute() or ".." in root.parts:
            raise ValueError("agent_workspace_root must be an absolute directory without '..'")
        target = PurePosixPath(self.agent_workspace_container_target)
        if not target.is_absolute() or str(target) == "/" or ".." in target.parts:
            raise ValueError("agent_workspace_target must be an absolute directory")
        for mount in self.mounts:
            other = PurePosixPath(mount.target)
            if target == other or target in other.parents or other in target.parents:
                raise ValueError(f"agent_workspace_target overlaps a mount: {other}")
        return self

    @model_validator(mode="after")
    def validate_state_dir(self) -> "SmolvmConfig":
        root = self.state_dir_root
        if root is not None and (not root.is_absolute() or ".." in root.parts):
            raise ValueError("state_dir_root must be an absolute directory without '..'")
        return self

    @property
    def agent_workspace_container_target(self) -> str:
        """Return the guest path the per-sandbox workspace is mounted at."""
        return self.agent_workspace_target or f"{self.runtime_home.rstrip('/')}/agent_work"

    @property
    def network_requested(self) -> bool:
        """Whether any configured knob needs the guest to have a network stack."""
        return bool(
            self.net
            or self.ports
            or self.allow_hosts
            or self.allow_host_patterns
            or self.allow_cidrs
            or self.deny_cidrs
            or self.allow_private
            or self.guest_subnet is not None
            or self.block_private
            or self.outbound_localhost_only
            or self.credentials
        )

    @property
    def resolved_environment(self) -> dict[str, str]:
        """Guest env with ``OMNIGENT_RUNNER_ENV_PASSTHROUGH`` derived.

        The server's runner spawns a harness with a filtered environment: only
        allowlisted names, harness credential names, names the sandbox config
        references, and names in ``OMNIGENT_RUNNER_ENV_PASSTHROUGH`` survive. A
        harness that reads its own variables would otherwise lose them between
        the guest and the harness.

        :returns: The env mapping to pass to ``machine create``.
        """
        env = dict(self.environment)
        passthrough_name = "OMNIGENT_RUNNER_ENV_PASSTHROUGH"
        explicit = [
            name.strip() for name in env.get(passthrough_name, "").split(",") if name.strip()
        ]
        derived = (
            [key.env_var for key in self.keys]
            + [binding.env_var for binding in self.credentials]
            + list(self.env)
            + [name for name in env if name != passthrough_name]
        )
        merged = list(dict.fromkeys([*explicit, *derived]))
        if merged:
            env[passthrough_name] = ",".join(merged)
        return env


def profile_config_model(provider_id: str) -> type[SmolvmConfig]:
    """Bind the registered identity into an alias's validated config model."""
    return create_model(
        f"SmolvmConfig_{provider_id.replace('-', '_')}",
        __base__=SmolvmConfig,
        __module__=__name__,
        provider_id=(Literal[provider_id], Field(default=provider_id, exclude=True)),
    )
