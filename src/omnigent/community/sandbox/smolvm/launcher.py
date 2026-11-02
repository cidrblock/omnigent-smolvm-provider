"""Managed Omnigent hosts in smolvm microVMs.

Uses the smolvm CLI rather than a daemon: each sandbox is a machine with its own
guest kernel, its own disk, and an egress policy enforced by the host-side
network stack rather than by anything the guest can edit.
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import click
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

#: Where the provider records the host ports it handed this machine.
_PORTS_LABEL = "omnigent.ports"

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


def _port_available(port: int) -> bool:
    """Whether this host can bind *port* on every interface right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError:
            return False
    return True


@contextmanager
def _port_lock() -> Iterator[None]:
    """Serialize port selection across concurrent provisions.

    Probing and creating are separate steps, so without a lock two launches
    could pick the same free port and the second would fail at start.
    """
    path = Path(tempfile.gettempdir()) / f"omnigent-smolvm-ports-{os.getuid()}.lock"
    with open(path, "a+", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _private_directory(path: Path) -> None:
    """Create a mode-0700 directory, reusing one an earlier sandbox left."""
    try:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.chmod(0o700)
    except OSError as exc:
        raise click.ClickException(
            f"smolvm agent workspace directory is unusable: {path}: {exc.strerror or exc}"
        ) from None


class SmolvmSandboxLauncher(ExecModelHostLauncher):
    """Provision, exec into, resume, and remove managed smolvm sandboxes."""

    provider = "smolvm"

    def __init__(self, *, config: SmolvmConfig):
        self.config = config
        self.provider = config.provider_id

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
        """Values this provider knows and must never echo back in an error.

        Secrets themselves are opaque here — smolvm resolves them from the
        keychain, the host environment, or a file — so this only covers the
        plain values the config itself carries.
        """
        return [
            value
            for name, value in self.config.resolved_environment.items()
            if name != "OMNIGENT_RUNNER_ENV_PASSTHROUGH" and value and len(value) >= 6
        ]

    def _failed(
        self, action: str, result: subprocess.CompletedProcess[str]
    ) -> click.ClickException:
        """Build an error that says what failed *and* why smolvm failed."""
        detail = _error_detail(result, self._secrets())
        return click.ClickException(f"{action}: {detail}" if detail else action)

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
        self,
        machine_name: str,
        safe_name: str,
        workspace: Path | None,
        dynamic_ports: list[int] | None = None,
    ) -> list[str]:
        """Return the ``machine create`` arguments for this profile.

        Secrets travel as references only (``--secret-keychain``,
        ``--secret-env``, ``--secret-file``): smolvm resolves each one on the
        host at machine start, so the value is never in this argv, in the
        machine record, or in ``machine ls --json``. Credential bindings add
        their own source flag plus ``--credential``; the guest sees only the
        placeholder.
        """
        config = self.config
        dynamic_ports = dynamic_ports or []
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
        for cidr in config.allow_private:
            args.extend(["--allow-private", cidr])
        if config.guest_subnet is not None:
            args.extend(["--guest-subnet", config.guest_subnet])
        if config.block_private:
            args.append("--block-private")
        if config.outbound_localhost_only:
            args.append("--outbound-localhost-only")
        for secret in config.secrets:
            args.extend(secret.arguments())
        for binding in config.credentials:
            args.extend(binding.source_arguments())
            args.extend(["--credential", binding.render()])
        for mapping in config.ports:
            args.extend(["--port", mapping])
        for port in dynamic_ports:
            args.extend(["--port", f"{port}:{port}"])
        if dynamic_ports:
            args.extend(["--label", f"{_PORTS_LABEL}={','.join(str(p) for p in dynamic_ports)}"])
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
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-.")[:48] or "session"
        machine_name = f"omni-{safe_name}-{secrets.token_hex(4)}"
        workspace = self._workspace_directory(safe_name)
        with _port_lock():
            dynamic_ports = self._allocate_ports()
            created = self._smolvm(
                "machine",
                "create",
                *self._create_args(machine_name, safe_name, workspace, dynamic_ports),
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
            self._write_sandbox_info(machine_name, workspace, dynamic_ports)
            if self.config.bootstrap_command is not None:
                self.run(machine_name, self.config.bootstrap_command)
        except BaseException:
            self._discard(machine_name)
            raise
        return machine_name

    # ------------------------------------------------------------------ ports

    def _claimed_ports(self) -> set[int]:
        """Host ports already promised to a machine this provider created."""
        result = self._smolvm("machine", "ls", "--json")
        if result.returncode:
            return set()
        try:
            machines = json.loads(result.stdout or "[]")
        except ValueError:
            return set()
        ports: set[int] = set()
        if not isinstance(machines, list):
            return ports
        for machine in machines:
            if not isinstance(machine, dict):
                continue
            labels = machine.get("labels") or {}
            if not isinstance(labels, dict) or labels.get(_MANAGED_LABEL) != "true":
                continue
            for item in str(labels.get(_PORTS_LABEL, "")).split(","):
                if item.strip().isdigit():
                    ports.add(int(item.strip()))
            for entry in machine.get("published_ports") or []:
                if isinstance(entry, dict) and isinstance(entry.get("host"), int):
                    ports.add(entry["host"])
        return ports

    def _allocate_ports(self) -> list[int]:
        """Pick this machine's slice of free host ports from the configured range.

        Host ports are machine-global, so a shared profile cannot use a fixed
        pool: the second sandbox would collide with the first. Each machine asks
        for its own free ports instead, and the mapping is published to the
        guest and to the machine's labels.

        :returns: Host ports, each mapped to the same guest port.
        :raises click.ClickException: When the range cannot supply the request.
        """
        count = self.config.dynamic_port_count
        if not count:
            return []
        assert self.config.dynamic_port_range is not None  # validated by config
        start, end = self.config.dynamic_port_range
        claimed = self._claimed_ports()
        chosen: list[int] = []
        for port in range(start, end + 1):
            if len(chosen) == count:
                break
            if port in claimed or not _port_available(port):
                continue
            chosen.append(port)
        if len(chosen) < count:
            raise click.ClickException(
                f"smolvm found only {len(chosen)} of {count} free host ports in "
                f"{start}-{end}; widen dynamic_port_range or free some ports"
            )
        return chosen

    # ----------------------------------------------------------- sandbox file

    def _sandbox_info(self, machine_name: str, dynamic_ports: list[int]) -> str:
        """Render the "about your sandbox" note the agent reads first."""
        config = self.config
        subnet = config.guest_subnet or "100.96.0.0/30"
        gateway = str(next(iter(ipaddress.ip_network(subnet).hosts())))
        lines = [
            "# About your sandbox",
            "",
            "You are inside a microVM, not a container on the host. It has its own",
            "kernel, its own disk, and a network policy the guest cannot change.",
            "",
            "| Fact | Value |",
            "|---|---|",
            f"| Provider | `{self.provider}` |",
            f"| Machine | `{machine_name}` |",
            f"| Image | `{config.image}` |",
            f"| Host gateway | `{gateway}` |",
            f"| Working directory | `{config.workdir or '/'}` |",
        ]
        if config.agent_workspace:
            lines.append(f"| Agent work directory | `{config.agent_workspace_container_target}` |")
        lines.extend(
            [
                "",
                "## Ports",
                "",
            ]
        )
        if dynamic_ports:
            lines.append(
                "The host publishes these ports to this machine. Serve on the guest"
                " port; the human opens the host port."
            )
            lines.append("")
            lines.append("| Host | Guest | Host URL |")
            lines.append("|---|---|---|")
            for port in dynamic_ports:
                lines.append(f"| {port} | {port} | http://127.0.0.1:{port}/ |")
        else:
            lines.append(
                "No ports are published. A listener inside the guest is reachable"
                " from the guest only."
            )
        lines.extend(
            [
                "",
                "## Egress",
                "",
            ]
        )
        rules: list[str] = []
        if config.block_private:
            rules.append("the LAN, cloud metadata, and CGNAT are blocked")
        for cidr in config.allow_private:
            rules.append(f"`{cidr}` is re-opened under that block")
        for cidr in config.allow_cidrs:
            rules.append(f"`{cidr}` is allowed")
        for cidr in config.deny_cidrs:
            rules.append(f"`{cidr}` is denied")
        named = list(config.allow_hosts) + list(config.allow_host_patterns)
        if named:
            rules.append(
                "hostnames are default-deny; only these resolve: "
                + ", ".join(f"`{name}`" for name in named)
            )
            rules.append(
                "any other name does not resolve, and a bare IP address has no"
                " route, so retrying or substituting an address will not help"
            )
        if not rules:
            rules.append("egress is unrestricted while the machine has a network")
        lines.extend(f"- {rule}" for rule in rules)
        lines.extend(
            [
                "",
                "The host loopback is reached through the gateway address above, not",
                "through 127.0.0.1 inside this machine.",
                "",
            ]
        )
        return "\n".join(lines)

    def _write_sandbox_info(
        self, machine_name: str, workspace: Path | None, dynamic_ports: list[int]
    ) -> None:
        """Place the sandbox note where the agent and the operator can read it."""
        try:
            info = self._sandbox_info(machine_name, dynamic_ports)
        except ValueError:  # a malformed subnet is reported by config validation
            return
        if workspace is not None:
            try:
                (workspace / "sandbox-info.md").write_text(info, encoding="utf-8")
            except OSError:
                _LOGGER.debug("could not write the host-side sandbox note", exc_info=True)
        marker = f"OMNIGENT_SANDBOX_{secrets.token_hex(8)}"
        script = (
            f"cat > /root/sandbox-info.md <<'{marker}'\n{info}{marker}\n"
            "chmod 0644 /root/sandbox-info.md\n"
        )
        self.run(machine_name, script, check=False)

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
        script = command if command.endswith("\n") else f"{command}\n"
        result = self._smolvm(
            "machine",
            "exec",
            "-i",
            "--name",
            sandbox_id,
            "--",
            "sh",
            "-s",
            sandbox_id=sandbox_id,
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
