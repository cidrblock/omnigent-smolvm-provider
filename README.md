# omnigent-smolvm-provider

An Omnigent sandbox provider that runs each managed host in its own
[smolvm](https://github.com/smol-machines/smolvm) microVM: a separate guest
kernel per sandbox, an egress policy enforced outside the guest, and no root,
no daemon, and no container engine in the trust path.

## Why a microVM

The Podman provider fences a container's network namespace with an OCI hook and
limits what the in-container agent can reach with `cap_drop` and pasta. Both are
policy *inside* the workload's own control: the agent can start its own engine,
and `podman build` never runs the hook at all. A microVM moves the boundary out
of the workload — the guest cannot edit the host-side egress gateway, and a
container the agent starts inside the guest is still inside the same boundary.

## Requirements

- `smolvm` on `PATH` (or `binary:` pointing at it)
- Linux with `/dev/kvm`, or macOS 11+ on Apple Silicon, or Windows with WHP

## Configuration

```yaml
- provider: smolvm
  smolvm:
    image: alpine:3.20
    cpus: 4
    memory_mib: 8192
    ports: ["8080:8080"]
    allow_hosts: ["api.github.com"]
    allow_host_patterns: ["*.example.com"]
    block_private: true
    mounts:
      - {source: /home/me/repo, target: /root/workspace, mode: rw}
    keys:
      - {keyring: Agents, description: github, env_var: GH_TOKEN}
    agent_workspace: true
    agent_workspace_root: /home/me/agent_work
```

Every secret is resolved on the host at exec time and delivered with
`--secret-env`, so the value never appears in the machine record, the Smolfile,
a log, or the process argv.

## Deliberate omissions

`smolvm` supports credentials brokered at the gateway (`--credential`),
checkpoints, branching, and named inter-VM networks. This provider does not use
them yet; the profile schema is intentionally small and validators reject
anything it cannot honour.
