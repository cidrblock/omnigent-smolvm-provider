"""Contract tests for the managed smolvm lifecycle and secret-safe exec path."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import click
from omnigent.community import sandbox as sandbox_namespace
from omnigent.onboarding.sandboxes.base import SandboxGoneError
from pydantic import ValidationError

# The host may already have an older wheel installed. Exercise this checkout's
# source first without replacing the running Omnigent service's plugin.
sandbox_namespace.__path__.insert(
    0, str(Path(__file__).resolve().parents[1] / "src/omnigent/community/sandbox")
)

from omnigent.community.sandbox.smolvm.config import BindMount, SmolvmConfig
from omnigent.community.sandbox.smolvm.config import MAX_PORT_MAPPINGS
from omnigent.community.sandbox.smolvm.config import profile_config_model
from omnigent.community.sandbox.smolvm.launcher import SmolvmSandboxLauncher
from omnigent.community.sandbox.smolvm.plugin import get_contribution

_MODULE = "omnigent.community.sandbox.smolvm.launcher"


def completed(args, code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args, code, stdout, stderr)


def not_found(args):
    return completed(args, 1, "", json.dumps({"error": {"code": "NOT_FOUND", "message": "vm not found"}}))


def status_record(name, state="running", labels=None, published_ports=()):
    return json.dumps(
        {
            "name": name,
            "state": state,
            "labels": labels
            if labels is not None
            else {"omnigent.managed": "true", "omnigent.provider": "smolvm"},
            "published_ports": list(published_ports),
        }
    )


class Recorder:
    """Stand-in for ``subprocess.run`` that answers by subcommand."""

    def __init__(self, *, state="running", labels=None, create_code=0, start_code=0,
                 exec_code=0, exec_stdout="", exec_stderr="", status_code=0):
        self.calls = []
        self.state = state
        self.labels = labels
        self.create_code = create_code
        self.start_code = start_code
        self.exec_code = exec_code
        self.exec_stdout = exec_stdout
        self.exec_stderr = exec_stderr
        self.status_code = status_code

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        verb = " ".join(argv)
        if "--version" in argv:
            return completed(argv, 0, "smolvm 1.33.0\n")
        if "machine create" in verb:
            return completed(argv, self.create_code, "", "" if not self.create_code else '{"error":{"code":"CREATE_FAILED","message":"no kvm"}}')
        if "machine start" in verb:
            return completed(argv, self.start_code)
        if "machine status" in verb:
            if self.status_code:
                return not_found(argv)
            name = argv[argv.index("--name") + 1]
            return completed(argv, 0, status_record(name, self.state, self.labels))
        if "machine exec" in verb:
            return completed(argv, self.exec_code, self.exec_stdout, self.exec_stderr)
        return completed(argv, 0)

    def call_containing(self, *parts):
        """Return the argv of the latest call whose joined command matches."""
        matches = [
            argv for argv, _ in self.calls if all(part in " ".join(argv) for part in parts)
        ]
        return matches[-1] if matches else None


class SmolvmConfigTests(unittest.TestCase):
    def test_image_and_binary_cannot_be_read_as_options(self):
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="--privileged")
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="alpine", binary="-nonsense")

    def test_allow_hosts_are_bare_hostnames(self):
        self.assertEqual(SmolvmConfig(image="a", allow_hosts=["api.github.com"]).allow_hosts,
                         ["api.github.com"])
        for bad in ("https://api.github.com", "api.github.com:443", "a b", "*.example.com"):
            with self.assertRaises(ValidationError):
                SmolvmConfig(image="a", allow_hosts=[bad])
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", allow_hosts=["a.example", "a.example"])

    def test_allow_host_patterns_accept_one_leading_wildcard(self):
        config = SmolvmConfig(image="a", allow_host_patterns=["*.example.com", "exact.example"])
        self.assertEqual(len(config.allow_host_patterns), 2)
        for bad in ("*", "a.*.example", "https://*.example"):
            with self.assertRaises(ValidationError):
                SmolvmConfig(image="a", allow_host_patterns=[bad])

    def test_cidrs_are_networks_and_reject_shell_fragments(self):
        config = SmolvmConfig(image="a", deny_cidrs=["10.0.0.0/8", "fd00::/8"])
        self.assertEqual(config.deny_cidrs, ["10.0.0.0/8", "fd00::/8"])
        for bad in ("10.0.0.0/8; id", "$(id)", "not-an-address"):
            with self.assertRaises(ValidationError):
                SmolvmConfig(image="a", allow_cidrs=[bad])

    def test_allow_private_reuses_cidr_validation(self):
        config = SmolvmConfig(image="a", block_private=True, allow_private=["100.96.0.0/30"])
        self.assertEqual(config.allow_private, ["100.96.0.0/30"])
        for bad in ("100.96.0.1", "$(id)", "not-a-cidr"):
            with self.assertRaises(ValidationError):
                SmolvmConfig(image="a", allow_private=[bad])
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", allow_private=["10.0.0.0/8", "10.0.0.0/8"])

    def test_guest_subnet_must_be_a_small_ipv4_link_network(self):
        config = SmolvmConfig(image="a", guest_subnet="100.96.0.0/30")
        self.assertEqual(config.guest_subnet, "100.96.0.0/30")
        for bad in ("0.0.0.0/0", "100.96.0.0/31", "fd00::/120", "100.96.0.0", "100.96.0.1/30"):
            with self.assertRaises(ValidationError):
                SmolvmConfig(image="a", guest_subnet=bad)

    def test_port_ranges_must_be_one_to_one(self):
        SmolvmConfig(image="a", ports=["8080:80", "9000-9002:9000-9002", "7000:7000/udp"])
        for bad in ("8080", "8080:80:90", "9000-9002:9100", "0:80", "65536:80",
                    "8080:80/icmp", "a:b"):
            with self.assertRaises(ValidationError):
                SmolvmConfig(image="a", ports=[bad])

    def test_port_mapping_cap_is_enforced(self):
        at_cap = [f"{10000 + index}:{index + 1}" for index in range(MAX_PORT_MAPPINGS)]
        SmolvmConfig(image="a", ports=at_cap)
        over = [f"{20000 + index}:{index + 1}" for index in range(MAX_PORT_MAPPINGS + 1)]
        with self.assertRaisesRegex(ValidationError, "smolvm allows"):
            SmolvmConfig(image="a", ports=over)

    def test_mount_targets_must_be_distinct_and_non_overlapping(self):
        first = BindMount(source=Path("/tmp/a"), target="/work/a")
        nested = BindMount(source=Path("/tmp/b"), target="/work/a/b")
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", mounts=[first, nested])
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", mounts=[first, first])

    def test_mount_source_must_be_absolute_without_parent_traversal(self):
        with self.assertRaises(ValidationError):
            BindMount(source=Path("relative"), target="/work")
        with self.assertRaises(ValidationError):
            BindMount(source=Path("/tmp/../etc"), target="/work")

    def test_agent_workspace_options_require_the_feature(self):
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", agent_workspace_root=Path("/tmp/work"))
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", agent_workspace=True)
        config = SmolvmConfig(
            image="a", agent_workspace=True, agent_workspace_root=Path("/tmp/work")
        )
        self.assertEqual(config.agent_workspace_container_target, "/root/agent_work")

    def test_agent_workspace_target_cannot_overlap_a_mount(self):
        with self.assertRaises(ValidationError):
            SmolvmConfig(
                image="a",
                agent_workspace=True,
                agent_workspace_root=Path("/tmp/work"),
                agent_workspace_target="/work",
                mounts=[BindMount(source=Path("/tmp/a"), target="/work/repo")],
            )

    def test_env_names_are_validated_and_duplicates_rejected(self):
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", env=["GH_TOKEN=secret"])
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", env=["GH_TOKEN", "GH_TOKEN"])
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", environment={"BAD NAME": "x"})
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", environment={"OK": "line\nbreak"})

    def test_keyring_names_cannot_collide_with_env(self):
        key = {"key_name": "app", "service": "svc", "env_var": "APP_API_KEY"}
        SmolvmConfig(image="a", keys=[key])
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", keys=[key, key])
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", env=["APP_API_KEY"], keys=[key])
        with self.assertRaises(ValidationError):
            SmolvmConfig(image="a", environment={"APP_API_KEY": "x"}, keys=[key])

    def test_profile_model_binds_the_alias_identity(self):
        model = profile_config_model("smolvm-python")
        config = model(image="alpine")
        self.assertEqual(config.provider_id, "smolvm-python")
        with self.assertRaises(ValidationError):
            model(image="alpine", provider_id="smolvm")

    def test_runner_passthrough_is_derived_from_env_and_keys(self):
        config = SmolvmConfig(
            image="a",
            env=["GH_TOKEN"],
            environment={"EXTRA": "1"},
            keys=[{"key_name": "k", "service": "s", "env_var": "APP_KEY"}],
        )
        names = config.resolved_environment["OMNIGENT_RUNNER_ENV_PASSTHROUGH"].split(",")
        self.assertEqual(names, ["APP_KEY", "GH_TOKEN", "EXTRA"])
        self.assertEqual(SmolvmConfig(image="a", environment={}).resolved_environment, {})


class SmolvmLauncherTests(unittest.TestCase):
    def setUp(self):
        self.launcher = SmolvmSandboxLauncher(
            config=SmolvmConfig(image="alpine:3.20", env=["GH_TOKEN"])
        )

    # ------------------------------------------------------------------ plugin

    def test_contribution_uses_current_registry_contract(self):
        contribution = get_contribution()
        metadata = contribution.providers["smolvm"]
        self.assertIs(metadata.config_model, SmolvmConfig)
        self.assertTrue(self.launcher.capabilities.managed_launch)
        self.assertTrue(self.launcher.capabilities.resume_stopped)
        self.assertTrue(self.launcher.capabilities.file_copy)

    def test_configured_aliases_have_independent_launcher_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text("""sandbox:
  providers:
    - provider: smolvm-python
      smolvm-python: {image: alpine:3.20}
    - provider: smolvm_node
      smolvm_node: {image: alpine:3.20}
    - provider: podman
""")
            with patch.dict(os.environ, {"OMNIGENT_CONFIG": str(config_path)}):
                providers = get_contribution().providers
            self.assertEqual(set(providers), {"smolvm", "smolvm-python", "smolvm_node"})
            for alias in ("smolvm-python", "smolvm_node"):
                metadata = providers[alias]
                self.assertEqual(
                    metadata.config_model.__module__,
                    "omnigent.community.sandbox.smolvm.config",
                )
                config = metadata.config_model(image="alpine")
                self.assertEqual(SmolvmSandboxLauncher(config=config).provider, alias)
                with self.assertRaises(ValidationError):
                    metadata.config_model(image="alpine", provider_id="smolvm")

    def test_profile_registration_rejects_duplicate_names(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(
                "sandbox:\n  providers:\n"
                "    - provider: smolvm-python\n    - provider: smolvm-python\n"
            )
            with patch.dict(os.environ, {"OMNIGENT_CONFIG": str(config_path)}):
                with self.assertRaisesRegex(ValueError, "duplicate smolvm profile"):
                    get_contribution()

    def test_aliases_resolve_through_omnigent_deployment_parser(self):
        import yaml
        from omnigent.onboarding.sandboxes import registry
        from omnigent.server.managed_hosts import parse_sandbox_config

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text("""sandbox:
  providers:
    - provider: smolvm-python
      server_url: http://127.0.0.1:6767
      smolvm-python: {image: alpine:3.20}
    - provider: smolvm-node
      server_url: http://127.0.0.1:6767
      smolvm-node: {image: alpine:3.20}
""")
            with patch.dict(os.environ, {"OMNIGENT_CONFIG": str(config_path)}):
                registry.reset_plugin_state_for_tests()
                try:
                    deployment = parse_sandbox_config(
                        yaml.safe_load(config_path.read_text())["sandbox"]
                    )
                    self.assertEqual(
                        deployment.launchable_providers(), ("smolvm-python", "smolvm-node")
                    )
                    for alias in deployment.launchable_providers():
                        launcher = deployment.for_provider(alias).launcher_factory()
                        self.assertEqual(launcher.provider, alias)
                finally:
                    registry.reset_plugin_state_for_tests()

    # ------------------------------------------------------------------ create

    @patch(f"{_MODULE}.secrets.token_hex", return_value="aabbccdd")
    @patch(f"{_MODULE}.subprocess.run")
    def test_create_args_carry_labels_policy_ports_and_mounts(self, run, _token):
        recorder = Recorder()
        run.side_effect = recorder
        with tempfile.TemporaryDirectory() as directory:
            launcher = SmolvmSandboxLauncher(
                config=SmolvmConfig(
                    image="alpine:3.20",
                    cpus=2,
                    memory_mib=2048,
                    storage_gb=20,
                    overlay_gb=5,
                    ports=["8080:80"],
                    allow_hosts=["api.github.com"],
                    allow_host_patterns=["*.example.com"],
                    allow_cidrs=["192.0.2.0/24"],
                    deny_cidrs=["10.0.0.0/8"],
                    allow_private=["100.96.0.0/30"],
                    guest_subnet="100.96.0.0/30",
                    block_private=True,
                    net_backend="virtio-net",
                    environment={"EXTRA": "value"},
                    mounts=[BindMount(source=Path(directory), target="/data", mode="ro")],
                    init=["apk add curl"],
                )
            )
            machine = launcher.provision("session one")

        self.assertEqual(machine, "omni-session-one-aabbccdd")
        argv = recorder.call_containing("machine create")
        self.assertIsNotNone(argv)
        joined = " ".join(argv)
        self.assertIn("omnigent.managed=true", joined)
        self.assertIn("omnigent.provider=smolvm", joined)
        self.assertIn("omnigent.session-name=session-one", joined)
        self.assertIn("--cpus 2", joined)
        self.assertIn("--mem 2048", joined)
        self.assertIn("--storage 20", joined)
        self.assertIn("--overlay 5", joined)
        self.assertIn("--port 8080:80", joined)
        self.assertIn("--allow-host api.github.com", joined)
        self.assertIn("--allow-host-pattern *.example.com", joined)
        self.assertIn("--allow-cidr 192.0.2.0/24", joined)
        self.assertIn("--deny-cidr 10.0.0.0/8", joined)
        self.assertIn("--allow-private 100.96.0.0/30", joined)
        self.assertIn("--guest-subnet 100.96.0.0/30", joined)
        self.assertIn("--block-private", joined)
        self.assertIn(f"-v {directory}:/data:ro", joined)
        self.assertIn("--init", joined)
        self.assertIn("-e EXTRA=value", joined)
        self.assertIn("--net", joined)

    def test_network_flag_follows_the_knobs(self):
        self.assertTrue(SmolvmConfig(image="a").network_requested)
        self.assertFalse(SmolvmConfig(image="a", net=False).network_requested)
        self.assertTrue(SmolvmConfig(image="a", net=False, ports=["8080:80"]).network_requested)

    @patch(f"{_MODULE}.secrets.token_hex", return_value="aabbccdd")
    @patch(f"{_MODULE}.subprocess.run")
    def test_create_failure_does_not_start_or_leak_a_machine(self, run, _token):
        recorder = Recorder(create_code=1)
        run.side_effect = recorder
        with self.assertRaises(click.ClickException) as caught:
            self.launcher.provision("session")
        self.assertIn("no kvm", str(caught.exception))
        self.assertIsNone(recorder.call_containing("machine start"))
        self.assertIsNone(recorder.call_containing("machine delete"))

    @patch(f"{_MODULE}.secrets.token_hex", return_value="aabbccdd")
    @patch(f"{_MODULE}.subprocess.run")
    def test_start_failure_discards_the_machine(self, run, _token):
        recorder = Recorder(start_code=1)
        run.side_effect = recorder
        with self.assertRaises(click.ClickException):
            self.launcher.provision("session")
        self.assertIsNotNone(recorder.call_containing("machine delete"))
        self.assertIsNotNone(recorder.call_containing("machine stop"))

    @patch(f"{_MODULE}.secrets.token_hex", return_value="aabbccdd")
    @patch(f"{_MODULE}.subprocess.run")
    def test_bootstrap_failure_discards_the_machine(self, run, _token):
        recorder = Recorder()
        run.side_effect = recorder
        launcher = SmolvmSandboxLauncher(
            config=SmolvmConfig(image="alpine", bootstrap_command="false")
        )
        # The exec that runs the bootstrap command fails; the machine must go.
        baseline = recorder.__call__

        def failing_exec(argv, **kwargs):
            if "machine exec" in " ".join(argv):
                return completed(argv, 1, "", "bootstrap failed")
            return baseline(argv, **kwargs)

        run.side_effect = failing_exec
        with self.assertRaises(click.ClickException):
            launcher.provision("session")
        self.assertIsNotNone(recorder.call_containing("machine delete"))

    @patch(f"{_MODULE}.secrets.token_hex", return_value="aabbccdd")
    @patch(f"{_MODULE}.subprocess.run")
    def test_agent_workspace_is_private_and_labelled(self, run, _token):
        recorder = Recorder()
        run.side_effect = recorder
        with tempfile.TemporaryDirectory() as directory:
            launcher = SmolvmSandboxLauncher(
                config=SmolvmConfig(
                    image="alpine", agent_workspace=True, agent_workspace_root=Path(directory)
                )
            )
            machine = launcher.provision("session")
            workspace = Path(directory) / "session"
            self.assertTrue(workspace.is_dir())
            self.assertEqual(workspace.stat().st_mode & 0o777, 0o700)
            argv = recorder.call_containing("machine create")
            self.assertIn(f"omnigent.workspace={workspace}", " ".join(argv))
            self.assertIn(f"-v {workspace}:/root/agent_work:rw", " ".join(argv))
        self.assertEqual(machine, "omni-session-aabbccdd")

    @patch(f"{_MODULE}.secrets.token_hex", return_value="aabbccdd")
    @patch(f"{_MODULE}.subprocess.run")
    def test_secrets_are_absent_from_create_and_machine_record(self, run, _token):
        recorder = Recorder()
        run.side_effect = recorder
        with patch.object(
            SmolvmSandboxLauncher, "_keys", return_value={"APP_KEY": "s3cret-value"}
        ):
            launcher = SmolvmSandboxLauncher(
                config=SmolvmConfig(
                    image="alpine",
                    keys=[{"key_name": "k", "service": "s", "env_var": "APP_KEY"}],
                )
            )
            launcher.provision("session")
        create_argv = recorder.call_containing("machine create")
        self.assertNotIn("s3cret-value", " ".join(create_argv))
        self.assertNotIn("--secret", " ".join(create_argv))

    # -------------------------------------------------------------------- exec

    @patch(f"{_MODULE}.subprocess.run")
    def test_exec_feeds_the_script_over_stdin(self, run):
        recorder = Recorder(exec_stdout="hi\n")
        run.side_effect = recorder
        result = self.launcher.run("box", "echo hi")
        self.assertEqual(result.stdout, "hi\n")
        argv, kwargs = recorder.calls[-1]
        self.assertEqual(argv[-2:], ["sh", "-s"])
        self.assertNotIn("echo hi", " ".join(argv))
        self.assertEqual(kwargs["input"], "echo hi\n")
        self.assertIn("-i", argv)

    @patch(f"{_MODULE}.subprocess.run")
    def test_exec_delivers_secrets_per_run_not_in_argv(self, run):
        recorder = Recorder()
        run.side_effect = recorder
        with patch.object(
            SmolvmSandboxLauncher, "_keys", return_value={"APP_KEY": "s3cret-value"}
        ):
            launcher = SmolvmSandboxLauncher(
                config=SmolvmConfig(
                    image="alpine",
                    keys=[{"key_name": "k", "service": "s", "env_var": "APP_KEY"}],
                )
            )
            launcher.run("box", "env | grep APP_KEY")
        argv, kwargs = recorder.calls[-1]
        joined = " ".join(argv)
        self.assertIn("--secret-env APP_KEY=OMNIGENT_SECRET_APP_KEY", joined)
        self.assertNotIn("s3cret-value", joined)
        self.assertEqual(kwargs["env"]["OMNIGENT_SECRET_APP_KEY"], "s3cret-value")

    @patch(f"{_MODULE}.subprocess.run")
    def test_exec_failure_is_redacted(self, run):
        recorder = Recorder(exec_code=1, exec_stderr="denied value s3cret-value")
        run.side_effect = recorder
        with patch.object(
            SmolvmSandboxLauncher, "_keys", return_value={"APP_KEY": "s3cret-value"}
        ):
            launcher = SmolvmSandboxLauncher(
                config=SmolvmConfig(
                    image="alpine",
                    keys=[{"key_name": "k", "service": "s", "env_var": "APP_KEY"}],
                )
            )
            with self.assertRaises(click.ClickException) as caught:
                launcher.run("box", "false")
        message = str(caught.exception)
        self.assertIn("exit 1", message)
        self.assertNotIn("s3cret-value", message)
        self.assertIn("***", message)

    @patch(f"{_MODULE}.subprocess.run")
    def test_exec_check_false_returns_the_result(self, run):
        recorder = Recorder(exec_code=3, exec_stderr="boom")
        run.side_effect = recorder
        result = self.launcher.run("box", "false", check=False)
        self.assertEqual(result.returncode, 3)

    @patch(f"{_MODULE}.subprocess.run")
    def test_put_copies_into_the_machine(self, run):
        recorder = Recorder()
        run.side_effect = recorder
        self.launcher.put("box", Path("/tmp/src"), "/root/workspace")
        argv = recorder.call_containing("machine cp")
        self.assertIn("box:/root/workspace", argv)

    # --------------------------------------------------------------- lifecycle

    @patch(f"{_MODULE}.subprocess.run")
    def test_machine_rejects_unmanaged_and_foreign_machines(self, run):
        run.side_effect = Recorder(labels={})
        with self.assertRaisesRegex(click.ClickException, "without our label"):
            self.launcher.is_running("box")
        run.side_effect = Recorder(
            labels={"omnigent.managed": "true", "omnigent.provider": "smolvm-other"}
        )
        with self.assertRaisesRegex(click.ClickException, "another smolvm profile"):
            self.launcher.is_running("box")

    @patch(f"{_MODULE}.subprocess.run")
    def test_missing_machine_is_gone_on_resume_and_noop_on_terminate(self, run):
        run.side_effect = Recorder(status_code=1)
        with self.assertRaises(SandboxGoneError):
            self.launcher.resume("box")
        self.launcher.terminate("box")

    @patch(f"{_MODULE}.subprocess.run")
    def test_resume_starts_a_stopped_machine_unless_running(self, run):
        recorder = Recorder(state="stopped")

        def starting(argv, **kwargs):
            result = recorder(argv, **kwargs)
            if "machine start" in " ".join(argv):
                recorder.state = "running"
            return result

        run.side_effect = starting
        self.launcher.resume("box")
        self.assertIsNotNone(recorder.call_containing("machine start"))

        recorder = Recorder(state="running")
        run.side_effect = recorder
        self.launcher.resume("box")
        self.assertIsNone(recorder.call_containing("machine start"))

    @patch(f"{_MODULE}.subprocess.run")
    def test_resume_fails_when_the_started_machine_never_runs(self, run):
        run.side_effect = Recorder(state="stopped")
        with self.assertRaisesRegex(click.ClickException, "not running"):
            self.launcher.resume("box")

    @patch(f"{_MODULE}.subprocess.run")
    def test_terminate_stops_then_deletes_only_a_running_machine(self, run):
        recorder = Recorder(state="running")
        run.side_effect = recorder
        self.launcher.terminate("box")
        self.assertIsNotNone(recorder.call_containing("machine stop"))
        self.assertIsNotNone(recorder.call_containing("machine delete"))

        recorder = Recorder(state="stopped")
        run.side_effect = recorder
        self.launcher.terminate("box")
        self.assertIsNone(recorder.call_containing("machine stop"))
        self.assertIsNotNone(recorder.call_containing("machine delete"))

    @patch(f"{_MODULE}.subprocess.run")
    def test_machine_status_reports_a_missing_machine_as_config_error(self, run):
        # smolvm uses CONFIG_ERROR for this one verb, not NOT_FOUND; a deleted
        # sandbox must still read as gone.
        run.side_effect = lambda argv, **kwargs: completed(
            argv,
            1,
            "",
            json.dumps(
                {
                    "error": {
                        "code": "CONFIG_ERROR",
                        "message": "config operation failed: machine status: "
                        "machine 'box' not found",
                    }
                }
            ),
        )
        self.assertIsNone(self.launcher._machine("box"))
        self.assertFalse(self.launcher.is_running("box"))
        self.launcher.terminate("box")

    @patch(f"{_MODULE}.subprocess.run")
    def test_unrelated_config_error_is_not_mistaken_for_a_missing_machine(self, run):
        run.side_effect = lambda argv, **kwargs: completed(
            argv,
            1,
            "",
            json.dumps(
                {
                    "error": {
                        "code": "CONFIG_ERROR",
                        "message": "config operation failed: machine status: bad db",
                    }
                }
            ),
        )
        with self.assertRaisesRegex(click.ClickException, "bad db"):
            self.launcher.is_running("box")

    @patch(f"{_MODULE}.subprocess.run")
    def test_status_error_other_than_not_found_is_reported(self, run):
        run.side_effect = lambda argv, **kwargs: completed(
            argv, 1, "", '{"error":{"code":"DAEMON_DOWN","message":"cannot reach engine"}}'
        )
        with self.assertRaisesRegex(click.ClickException, "cannot reach engine"):
            self.launcher.is_running("box")

    # ----------------------------------------------------------------- prepare

    @patch(f"{_MODULE}.shutil.which", return_value=None)
    def test_prepare_requires_the_cli(self, _which):
        with self.assertRaisesRegex(click.ClickException, "CLI not found"):
            self.launcher.prepare()

    @patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/smolvm")
    @patch(f"{_MODULE}.subprocess.run")
    @patch(f"{_MODULE}.os.access", return_value=True)
    @patch(f"{_MODULE}.Path.exists", return_value=False)
    def test_prepare_requires_kvm(self, _exists, _access, run, _which):
        run.return_value = completed(["smolvm"], 0, "smolvm 1.33.0")
        with patch(f"{_MODULE}.sys.platform", "linux"):
            with self.assertRaisesRegex(click.ClickException, "/dev/kvm"):
                self.launcher.prepare()

    @patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/smolvm")
    @patch(f"{_MODULE}.subprocess.run")
    @patch(f"{_MODULE}.os.access", return_value=True)
    @patch(f"{_MODULE}.Path.exists", return_value=True)
    def test_prepare_rejects_a_file_mount_source(self, _exists, _access, run, _which):
        run.return_value = completed(["smolvm"], 0, "smolvm 1.33.0")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "file"
            source.write_text("x")
            launcher = SmolvmSandboxLauncher(
                config=SmolvmConfig(
                    image="alpine",
                    mounts=[BindMount(source=source, target="/data")],
                )
            )
            with self.assertRaisesRegex(click.ClickException, "must be an existing directory"):
                launcher.prepare()

    @patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/smolvm")
    @patch(f"{_MODULE}.subprocess.run")
    @patch(f"{_MODULE}.os.access", return_value=True)
    @patch(f"{_MODULE}.Path.exists", return_value=True)
    def test_prepare_rejects_a_missing_state_dir_root(self, _exists, _access, run, _which):
        run.return_value = completed(["smolvm"], 0, "smolvm 1.33.0")
        launcher = SmolvmSandboxLauncher(
            config=SmolvmConfig(image="alpine", state_dir_root=Path("/nonexistent/state"))
        )
        with self.assertRaisesRegex(click.ClickException, "state_dir_root"):
            launcher.prepare()

    @patch(f"{_MODULE}.shutil.which", return_value="/usr/bin/smolvm")
    @patch(f"{_MODULE}.subprocess.run")
    def test_prepare_passes_when_everything_is_present(self, run, _which):
        run.return_value = completed(["smolvm"], 0, "smolvm 1.33.0")
        with patch(f"{_MODULE}.sys.platform", "darwin"):
            self.launcher.prepare()
        self.assertTrue(run.called)

    # ------------------------------------------------------------------ state

    def test_state_dir_is_per_machine_only_when_configured(self):
        self.assertIsNone(self.launcher._state_dir("box"))
        launcher = SmolvmSandboxLauncher(
            config=SmolvmConfig(image="alpine", state_dir_root=Path("/srv/state"))
        )
        self.assertEqual(launcher._state_dir("box"), Path("/srv/state/box"))
        self.assertIsNone(launcher._state_dir(None))

    @patch(f"{_MODULE}.subprocess.run")
    def test_state_dir_is_passed_as_a_global_flag(self, run):
        recorder = Recorder()
        run.side_effect = recorder
        launcher = SmolvmSandboxLauncher(
            config=SmolvmConfig(image="alpine", state_dir_root=Path("/srv/state"))
        )
        launcher.is_running("box")
        argv = recorder.calls[-1][0]
        self.assertEqual(argv[1:3], ["--state-dir", "/srv/state/box"])
        self.assertEqual(argv[3:5], ["--error-format", "json"])

    @patch(f"{_MODULE}.subprocess.run")
    def test_every_call_requests_json_errors(self, run):
        recorder = Recorder()
        run.side_effect = recorder
        self.launcher.run("box", "true")
        for argv, _ in recorder.calls:
            self.assertIn("--error-format", argv)
            self.assertEqual(argv[argv.index("--error-format") + 1], "json")


if __name__ == "__main__":
    unittest.main()
