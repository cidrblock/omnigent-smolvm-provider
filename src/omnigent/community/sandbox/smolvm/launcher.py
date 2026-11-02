"""Managed Omnigent hosts in smolvm microVMs.

Uses the smolvm CLI rather than a daemon: each sandbox is a machine with its own
guest kernel, its own disk, and an egress policy enforced by the host-side
network stack rather than by anything the guest can edit.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import click
import keyring
from omnigent.onboarding.sandboxes.base import (
    ExecModelHostLauncher,
    RemoteCommandResult,
    SandboxGoneError,
)
from omnigent.onboarding.sandboxes.types import SandboxCapabilities

from .config import SmolvmConfig


_LOGGER = logging.getLogger(__name__)

#: Labels stamped on every machine this provider creates, so a later launch (or
#: a human running ``smolvm machine ls``) can tell our machines from someone
#: else's and refuse to manage a stranger's.
_MANAGED_LABEL = "omnigent.managed"
_PROFILE_LABEL = "omnigent.provider"
_SESSION_LABEL = "omnigent.session-name"
_WORKSPACE_LABEL = "omnigent.workspace"

#: Prefix for the host-side environment variables that carry a keyring secret to
#: one ``machine exec``. smolvm resolves ``--secret-env GUEST=HOST`` from the
#: environment of the process it runs in, so the value crosses on the process
#: environment and never on argv, in the machine record, or on disk.
_SECRET_ENV_PREFIX = "OMNIGENT_SECRET_"

#: Upper bound on the CLI output quoted back in a user-facing error.
_MAX_DETAIL_CHARS = 500


def _redact(text: str, secrets_to_hide: list[str]) -> str:
    """Remove known credential values from CLI output.

    smolvm echoes parts of its own configuration in some failures (an invalid
    environment value, a bad mount spec), so the detail that makes an error
    diagnosable is exactly the detail that can leak a secret.
    """
    for secret in secrets_to_hide:
        if secret:
            text = text.replace(secret, "***")
    return text


def _error_detail(
    result: subprocess.CompletedProcess[str], secrets_to_hide: list[str]
) -> str:
    """Condense a failed invocation into one diagnosable clause.

    Inside ``--error-format json`` a provider-level failure arrives as
    ``{"error": {"code": …, "message": …}}``; anything else is the command's own
    stderr, where the last lines carry the reason.
    """
    raw = (result.stderr or "").strip()
    if not raw:
        return ""
    message = raw
    if raw.startswith("{"):
        try:
            payload = json.loads(raw)
            error = payload["error"]
            code = error.get("code", "")
            text = str(error.get("message", "")).strip()
            message = f"{text} ({code})" if code else text
        except (KeyError, TypeError, ValueError):
            message = raw
    lines = [line.strip() for line in message.splitlines() if line.strip()]
    detail = _redact(" ".join(lines[-3:]), secrets_to_hide)
    if len(detail) > _MAX_DETAIL_CHARS:
        detail = detail[:_MAX_DETAIL_CHARS] + "…"
    return detail


def _error_code(result: subprocess.CompletedProcess[str]) -> str | None:
    """Return the stable error code from a JSON failure, if smolvm sent one."""
    return _error_field(result, "code")


def _error_message(result: subprocess.CompletedProcess[str]) -> str:
    """Return the raw error message from a JSON failure, if smolvm sent one."""
    message = _error_field(result, "message")
    return message if isinstance(message, str) else ""


def _error_field(result: subprocess.CompletedProcess[str], name: str) -> object:
    """Return one field of ``{"error": {...}}`` from a failed invocation."""
    raw = (result.stderr or "").strip()
    if not raw.startswith("{"):
        return None
    try:
        return json.loads(raw)["error"][name]
    except (KeyError, TypeError, ValueError):
        return None


#: ``machine status`` reports a missing machine as ``CONFIG_ERROR`` carrying this
#: message, while every other verb uses ``NOT_FOUND``. Both mean "gone".
_MISSING_MACHINE = re.compile(r"machine '[^']*' not found\Z")


def _missing_machine(result: subprocess.CompletedProcess[str]) -> bool:
    """Whether a failed invocation says the machine does not exist."""
    if _error_code(result) == "NOT_FOUND":
        return True
    if _error_code(result) != "CONFIG_ERROR":
        return False
    return bool(_MISSING_MACHINE.search(_error_message(result).strip()))


def _private_directory(path: Path) -> None:
    """Create a mode-0700 directory, reusing one an earlier sandbox left."""
    try:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.chmod(0o700)
    except OSError as exc:
        raise click.ClickException(
            f"smolvm agent workspace directory is unusable: {path}: {exc.strerror or exc}"
        ) from None


def _secret_service_items(bus: object, collection_label: str | None) -> list[object]:
    """Return the items of one Secret Service collection (or of every one).

    Enumeration is defensive on purpose: a collection can hold a *stale* item
    path (the item was deleted while the collection index still listed it), and
    ``get_all_items()`` then raises for that entry, aborting the whole scan.

    :param bus: Open Secret Service bus from ``secretstorage.dbus_init()``.
    :param collection_label: Exact collection label to search, or ``None``.
    :returns: Items from the matching, unlocked collections.
    :raises ValueError: When a named collection is missing or locked.
    """
    import secretstorage

    all_collections = list(secretstorage.get_all_collections(bus))
    if collection_label is None:
        collections = all_collections
    else:
        collections = [c for c in all_collections if c.get_label() == collection_label]
        if not collections:
            raise ValueError(f"no keyring collection named {collection_label!r}")
    items: list[object] = []
    for collection in collections:
        if collection.is_locked():
            if collection_label is None:
                continue
            raise ValueError(
                f"keyring collection {collection_label!r} is locked; unlock it and retry"
            )
        try:
            candidates = list(collection.get_all_items())
        except Exception:  # noqa: BLE001 — index unreadable: skip this collection
            continue
        for item in candidates:
            try:
                item.get_label()
            except Exception:  # noqa: BLE001 — stale item path
                continue
            items.append(item)
    return items


def _keyring_description_password(description: str, collection_label: str | None = None) -> str:
    """Read one item by its visible label, optionally inside a named collection.

    :param description: The item's label, matched exactly.
    :param collection_label: Collection to search; ``None`` searches every
        unlocked collection.
    :returns: The stored secret as text.
    :raises ValueError: Missing/locked collection, no match, or several matches.
    """
    if sys.platform != "linux":
        raise ValueError("keyring lookups require Linux Secret Service")
    import secretstorage

    with closing(secretstorage.dbus_init()) as bus:
        matches = []
        for item in _secret_service_items(bus, collection_label):
            try:
                if item.get_label() == description:
                    matches.append(item)
            except Exception:  # noqa: BLE001 — stale item path
                continue
        where = f"collection {collection_label!r}" if collection_label else "any collection"
        if not matches:
            raise ValueError(f"no keyring item labelled {description!r} in {where}")
        if len(matches) != 1:
            raise ValueError(
                f"keyring item label {description!r} is ambiguous ({len(matches)} matches)"
            )
        item = matches[0]
        if item.is_locked():
            raise ValueError(f"keyring item {description!r} is locked")
        return item.get_secret().decode("utf-8")


def _keyring_label_password(label: str) -> str:
    """Read one item by label from any unlocked collection (legacy form)."""
    return _keyring_description_password(label, None)


class SmolvmSandboxLauncher(ExecModelHostLauncher):
    """Provision, exec into, resume, and remove managed smolvm sandboxes."""

    provider = "smolvm"

    def __init__(self, *, config: SmolvmConfig):
        self.config = config
        self.provider = config.provider_id
        self._key_values: dict[str, str] | None = None

    # ------------------------------------------------------------------ state

    def _state_dir(self, sandbox_id: str | None) -> Path | None:
        """Return the per-sandbox state directory, or ``None`` for the shared one.

        When ``state_dir_root`` is set each machine keeps its own machine store,
        image cache, and database under a directory named for the machine. That
        isolates two sandboxes completely, at the cost of pulling each image
        once per sandbox; the default shares the user's store and relies on
        unique machine names instead.
        """
        root = self.config.state_dir_root
        if root is None or sandbox_id is None:
            return None
        return root / sandbox_id

    def _smolvm(
        self,
        *args: str,
        sandbox_id: str | None = None,
        env: dict[str, str] | None = None,
        input: str | None = None,
        timeout: int | None = 60,
    ) -> subprocess.CompletedProcess[str]:
        """Run the smolvm CLI with the sandbox's state directory selected."""
        argv = [self.config.binary]
        state_dir = self._state_dir(sandbox_id)
        if state_dir is not None:
            argv.extend(["--state-dir", str(state_dir)])
        argv.extend(["--error-format", "json", *args])
        environment = dict(os.environ)
        if env:
            environment.update(env)
        try:
            return subprocess.run(
                argv,
                input=input,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environment,
            )
        except subprocess.TimeoutExpired:
            raise click.ClickException(
                f"smolvm command did not finish within {timeout}s"
            ) from None
        except OSError as exc:
            raise click.ClickException(
                f"smolvm command could not run: {exc.strerror or type(exc).__name__}"
            ) from None

    # ----------------------------------------------------------------- errors

    def _secrets(self) -> list[str]:
        """Values that must never reach a user-facing error message."""
        values = [
            value
            for name, value in self.config.resolved_environment.items()
            if name != "OMNIGENT_RUNNER_ENV_PASSTHROUGH" and value
        ]
        try:
            values.extend(self._keys().values())
        except click.ClickException:
            # A keyring miss is reported on its own path; the error we are
            # building must not turn into a different failure.
            pass
        return [value for value in values if len(value) >= 6]

    def _failed(
        self, action: str, result: subprocess.CompletedProcess[str]
    ) -> click.ClickException:
        """Build an error that says what failed *and* why smolvm failed."""
        detail = _error_detail(result, self._secrets())
        return click.ClickException(f"{action}: {detail}" if detail else action)

    # ----------------------------------------------------------------- secrets

    def _keys(self) -> dict[str, str]:
        """Read each requested credential without exporting it on the host."""
        if self._key_values is not None:
            return self._key_values
        values: dict[str, str] = {}
        for key in self.config.keys:
            try:
                if key.description is not None:
                    value = _keyring_description_password(key.description, key.keyring)
                elif key.item_label is not None:
                    value = _keyring_label_password(key.item_label)
                else:
                    assert key.key_name is not None  # validated by KeyringKey
                    value = keyring.get_password(key.service, key.key_name)
            except Exception as exc:
                # The message stays generic on purpose: keyring backends echo
                # lookups and paths, and this string reaches the UI/logs.
                _LOGGER.debug(
                    "keyring lookup failed for %s: %s: %s",
                    key.env_var,
                    type(exc).__name__,
                    exc,
                )
                raise click.ClickException(
                    f"Cannot read keyring entry for {key.env_var}"
                ) from None
            if not value or "\x00" in value:
                raise click.ClickException(
                    f"Missing or invalid keyring entry for {key.env_var}"
                )
            values[key.env_var] = value
        self._key_values = values
        return values

    def _secret_arguments(self) -> tuple[list[str], dict[str, str]]:
        """Return ``--secret-env`` references and the environment they resolve from.

        smolvm reads the host variable when the exec starts, so a rotated secret
        is picked up by the next command instead of requiring a machine restart.
        """
        args: list[str] = []
        environment: dict[str, str] = {}
        for name, value in self._keys().items():
            host_var = f"{_SECRET_ENV_PREFIX}{name}"
            args.extend(["--secret-env", f"{name}={host_var}"])
            environment[host_var] = value
        return args, environment

    # ------------------------------------------------------------------ config

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            managed_launch=True,
            programmatic_terminate=True,
            resume_stopped=True,
            multi_repo=True,
            git_clone_options=True,
            file_copy=True,
        )

    # ------------------------------------------------------------------- setup

    def prepare(self) -> None:
        """Check the CLI, the hypervisor, and every path this profile references."""
        if shutil.which(self.config.binary) is None:
            raise click.ClickException(f"smolvm CLI not found: {self.config.binary}")
        version = self._smolvm("--version", timeout=30)
        if version.returncode:
            raise self._failed("smolvm is not runnable", version)
        if sys.platform.startswith("linux"):
            kvm = Path("/dev/kvm")
            if not kvm.exists():
                raise click.ClickException(
                    "smolvm needs /dev/kvm; enable virtualization in the BIOS and load kvm_intel "
                    "or kvm_amd, or use a provider that does not require a hypervisor"
                )
            if not os.access(kvm, os.R_OK | os.W_OK):
                raise click.ClickException(
                    f"smolvm cannot open {kvm}; add this user to the 'kvm' group"
                )
        root = self.config.state_dir_root
        if root is not None:
            if not root.is_dir():
                raise click.ClickException(
                    f"smolvm state_dir_root must be an existing directory: {root}"
                )
            if not os.access(root, os.W_OK | os.X_OK):
                raise click.ClickException(
                    f"smolvm state_dir_root is not writable by this user: {root}"
                )
        if self.config.agent_workspace:
            workspace_root = self.config.agent_workspace_root
            assert workspace_root is not None  # validated by SmolvmConfig
            if not workspace_root.is_dir():
                raise click.ClickException(
                    f"smolvm agent workspace root must be an existing directory: {workspace_root}"
                )
            if not os.access(workspace_root, os.W_OK | os.X_OK):
                raise click.ClickException(
                    f"smolvm agent workspace root is not accessible to this user: {workspace_root}"
                )
        for mount in self.config.mounts:
            # smolvm mounts directories; a single-file source would silently
            # become a directory in the guest, so reject it here instead.
            if mount.source.is_symlink() or not mount.source.is_dir():
                raise click.ClickException(
                    f"smolvm mount source must be an existing directory: {mount.source}"
                )
            if not os.access(mount.source, os.R_OK | os.X_OK):
                raise click.ClickException(
                    f"smolvm mount source is not readable by this user: {mount.source}"
                )
        self._keys()

    def _workspace_directory(self, safe_name: str) -> Path | None:
        """Create and return this sandbox's private workspace, if configured."""
        if not self.config.agent_workspace:
            return None
        root = self.config.agent_workspace_root
        assert root is not None  # validated by SmolvmConfig
        workspace = root / safe_name
        _private_directory(workspace)
        return workspace

    # --------------------------------------------------------------- provision

    def _create_args(
        self, machine_name: str, safe_name: str, workspace: Path | None
    ) -> list[str]:
        """Return the ``machine create`` arguments for this profile.

        Secrets are deliberately absent: they are supplied per exec with
        ``--secret-env`` so a machine record never holds a reference that goes
        stale, and ``machine ls --json`` never shows one.
        """
        config = self.config
        args = [
            "--name",
            machine_name,
            "--image",
            config.image,
            "--label",
            f"{_MANAGED_LABEL}=true",
            "--label",
            f"{_PROFILE_LABEL}={self.provider}",
            "--label",
            f"{_SESSION_LABEL}={safe_name}",
            "--cpus",
            str(config.cpus),
            "--mem",
            str(config.memory_mib),
        ]
        if config.storage_gb is not None:
            args.extend(["--storage", str(config.storage_gb)])
        if config.overlay_gb is not None:
            args.extend(["--overlay", str(config.overlay_gb)])
        if config.network_requested:
            args.append("--net")
        if config.net_backend is not None:
            args.extend(["--net-backend", config.net_backend])
        for host in config.allow_hosts:
            args.extend(["--allow-host", host])
        for pattern in config.allow_host_patterns:
            args.extend(["--allow-host-pattern", pattern])
        for cidr in config.allow_cidrs:
            args.extend(["--allow-cidr", cidr])
        for cidr in config.deny_cidrs:
            args.extend(["--deny-cidr", cidr])
        if config.block_private:
            args.append("--block-private")
        if config.outbound_localhost_only:
            args.append("--outbound-localhost-only")
        for binding in config.credentials:
            args.extend(["--credential", binding.render()])
        for mapping in config.ports:
            args.extend(["--port", mapping])
        if workspace is not None:
            args.extend(["--label", f"{_WORKSPACE_LABEL}={workspace}"])
            args.extend(
                ["-v", f"{workspace}:{config.agent_workspace_container_target}:rw"]
            )
        for mount in config.mounts:
            args.extend(["-v", f"{mount.source}:{mount.target}:{mount.mode}"])
        for name, value in config.resolved_environment.items():
            args.extend(["-e", f"{name}={value}"])
        for name in config.env:
            if name in os.environ:
                args.extend(["-e", f"{name}={os.environ[name]}"])
        if config.ssh_agent:
            args.append("--ssh-agent")
        if config.user is not None:
            args.extend(["--user", config.user])
        if config.workdir is not None:
            args.extend(["--workdir", config.workdir])
        for command in config.init:
            args.extend(["--init", command])
        return args

    def provision(self, name: str) -> str:
        """Create and start a machine, returning its name as the sandbox id."""
        self._keys()
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-.")[:48] or "session"
        machine_name = f"omni-{safe_name}-{secrets.token_hex(4)}"
        workspace = self._workspace_directory(safe_name)
        created = self._smolvm(
            "machine",
            "create",
            *self._create_args(machine_name, safe_name, workspace),
            sandbox_id=machine_name,
            timeout=300,
        )
        if created.returncode:
            raise self._failed("smolvm could not create the managed sandbox", created)
        started = self._smolvm(
            "machine",
            "start",
            "--name",
            machine_name,
            sandbox_id=machine_name,
            timeout=self.config.startup_timeout_s,
        )
        if started.returncode:
            self._discard(machine_name)
            raise self._failed("smolvm could not start the managed sandbox", started)
        try:
            if not self.is_running(machine_name):
                raise click.ClickException(
                    "smolvm reported success but the sandbox is not running"
                )
            if self.config.bootstrap_command is not None:
                self.run(machine_name, self.config.bootstrap_command)
        except BaseException:
            self._discard(machine_name)
            raise
        return machine_name

    def _discard(self, machine_name: str) -> None:
        """Best-effort removal of a machine that never became usable."""
        self._smolvm("machine", "stop", "--name", machine_name, sandbox_id=machine_name)
        self._smolvm(
            "machine", "delete", "-f", "--name", machine_name, sandbox_id=machine_name
        )

    # ---------------------------------------------------------------- lifecycle

    def _machine(self, sandbox_id: str) -> dict[str, object] | None:
        """Return the machine record, or ``None`` when it does not exist.

        Refuses to manage a machine this provider did not create: the sandbox id
        arrives from the server, and a typo or a hand-written config must not
        let one profile adopt another's VM.
        """
        result = self._smolvm(
            "machine", "status", "--name", sandbox_id, "--json", sandbox_id=sandbox_id
        )
        if result.returncode:
            if _missing_machine(result):
                return None
            raise self._failed("smolvm could not inspect the managed sandbox", result)
        try:
            payload = json.loads(result.stdout or "{}")
        except ValueError as exc:
            raise click.ClickException("smolvm returned invalid machine metadata") from exc
        if not isinstance(payload, dict):
            raise click.ClickException("smolvm returned invalid machine metadata")
        labels = payload.get("labels") or {}
        if not isinstance(labels, dict):
            raise click.ClickException("smolvm returned invalid machine labels")
        if labels.get(_MANAGED_LABEL) != "true":
            raise click.ClickException("Refusing to manage a machine without our label")
        if labels.get(_PROFILE_LABEL, "smolvm") != self.provider:
            raise click.ClickException("Refusing to manage another smolvm profile's machine")
        return payload

    def is_running(self, sandbox_id: str) -> bool:
        """Return whether an existing managed machine is running."""
        machine = self._machine(sandbox_id)
        return machine is not None and machine.get("state") == "running"

    def resume(self, sandbox_id: str) -> None:
        """Start a stopped machine; its disks and filesystem persist across stops.

        No fence has to be reapplied: the egress policy lives in the machine
        configuration and the host-side network stack, not in a namespace that
        is rebuilt on start.
        """
        machine = self._machine(sandbox_id)
        if machine is None:
            raise SandboxGoneError("Managed smolvm sandbox no longer exists")
        if machine.get("state") != "running":
            started = self._smolvm(
                "machine",
                "start",
                "--name",
                sandbox_id,
                sandbox_id=sandbox_id,
                timeout=self.config.startup_timeout_s,
            )
            if started.returncode:
                raise self._failed("smolvm could not resume the managed sandbox", started)
            if not self.is_running(sandbox_id):
                raise click.ClickException(
                    "smolvm reported success but the resumed sandbox is not running"
                )

    def terminate(self, sandbox_id: str) -> None:
        """Stop and remove an owned machine; an already-removed one is fine."""
        machine = self._machine(sandbox_id)
        if machine is None:
            return
        if machine.get("state") == "running":
            stopped = self._smolvm(
                "machine", "stop", "--name", sandbox_id, sandbox_id=sandbox_id, timeout=120
            )
            if stopped.returncode:
                raise self._failed("smolvm could not stop the managed sandbox", stopped)
        removed = self._smolvm(
            "machine", "delete", "-f", "--name", sandbox_id, sandbox_id=sandbox_id, timeout=120
        )
        if removed.returncode and not _missing_machine(removed):
            raise self._failed("smolvm could not remove the managed sandbox", removed)

    # --------------------------------------------------------------------- exec

    def run(
        self, sandbox_id: str, command: str, *, check: bool = True
    ) -> RemoteCommandResult:
        """Execute a shell script over stdin, keeping secrets out of argv.

        The script is fed to ``sh -s`` rather than passed as ``sh -c``: the
        server starts the managed host through this method, and its launch token
        would otherwise be visible in the host's process list.
        """
        secret_args, secret_env = self._secret_arguments()
        script = command if command.endswith("\n") else f"{command}\n"
        result = self._smolvm(
            "machine",
            "exec",
            "-i",
            *secret_args,
            "--name",
            sandbox_id,
            "--",
            "sh",
            "-s",
            sandbox_id=sandbox_id,
            env=secret_env,
            input=script,
            timeout=None,
        )
        completed = RemoteCommandResult(
            returncode=result.returncode, stdout=result.stdout, stderr=result.stderr
        )
        if check and completed.returncode:
            detail = _error_detail(result, self._secrets())
            suffix = f": {detail}" if detail else ""
            raise click.ClickException(
                f"smolvm sandbox command failed (exit {completed.returncode}){suffix}"
            )
        return completed

    def put(self, sandbox_id: str, local_path: Path, remote_path: str) -> None:
        """Copy a local file into the machine."""
        result = self._smolvm(
            "machine",
            "cp",
            str(local_path),
            f"{sandbox_id}:{remote_path}",
            sandbox_id=sandbox_id,
            timeout=300,
        )
        if result.returncode:
            raise self._failed(f"smolvm could not copy {local_path} into the sandbox", result)
