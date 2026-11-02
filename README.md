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

## Reaching the server from the guest

The Omnigent server listens on host loopback, so the managed host needs a path
back out of the guest. `--net-backend virtio-net` gives the guest a link whose
first address is the host, and that address reaches host loopback:

```yaml
server_url: http://100.96.0.1:6767   # gateway of the default 100.96.0.0/30
net_backend: virtio-net
```

That gateway is in CGNAT space, which `block_private` also closes, so a fenced
profile has to re-open exactly that subnet:

```yaml
block_private: true
allow_private: ["100.96.0.0/30"]
```

Measured result of that pair: the gateway and the public internet are
reachable, and the host's LAN is not. With `tsi` (the default backend) the
gateway path does not exist and guest loopback is the guest's own. `guest_subnet`
pins the link subnet if `100.96.0.0/30` collides with a VPN on the host; the
gateway is always the first address of whatever subnet you pick.

## Images

`image:` takes a registry reference, a `docker save` archive, or an unpacked
rootfs directory. A locally built image is reachable without a registry:

```bash
podman save --format docker-archive \
  -o ~/.omnigent/sandbox/smolvm/omnigent-host-fedora-1.tar \
  localhost/omnigent-host:fedora-1
```

then set `image:` to that path. The image must contain the `omnigent` CLI —
the server starts the managed host through it. Archives are capped at 8 GiB by
smolvm unless the profile raises `--max-image-size`.

## Configuration

```yaml
- provider: smolvm
  smolvm:
    image: alpine:3.20
    cpus: 4
    memory_mib: 8192
    ports: ["8080:8080"]
    net_backend: virtio-net
    allow_hosts: ["api.github.com"]
    allow_host_patterns: ["*.example.com"]
    block_private: true
    allow_private: ["100.96.0.0/30"]
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

## Mounts, and why they are directories

smolvm exposes host directories, not single files (`-v` takes a directory
source; a file would silently become one). Profiles that need a specific file
in a specific place mount one staging directory and copy it over `/` with a
single `--init` command:

```yaml
mounts:
  - {source: /home/me/.omnigent/sandbox/smolvm/root, target: /root/.omnigent-sandbox, mode: ro}
init:
  - cp -a /root/.omnigent-sandbox/. / && chown -R root:root /root/workspace
```

`cp -a` preserves the host owner, and inside the guest that owner is a bare
uid nobody uses, so `chown` back to root is part of the command. The copy runs
once, on the machine's first start; machines already created keep what they
booted with.

## Lifecycle

A machine is a process on the host. If the Omnigent server's own service is
configured with `KillMode=control-group`, restarting it stops every machine
belonging to that unit. smolvm notices and reports those machines as
`stopped` rather than leaving a stale `running` record, so `resume()` starts
them again with their disks intact — but nothing restarts them automatically.
Machines started outside the unit's cgroup are unaffected.

## Deliberate omissions

`smolvm` supports credentials brokered at the gateway (`--credential`),
checkpoints, branching, and named inter-VM networks. This provider does not use
them yet; the profile schema is intentionally small and validators reject
anything it cannot honour.
