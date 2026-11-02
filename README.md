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
    net_backend: virtio-net
    allow_hosts: ["api.github.com"]
    allow_host_patterns: ["pypi.org", "*.pypi.org"]
    block_private: true
    allow_private: ["100.96.0.0/30"]
    # A per-session slice of host ports (see "Ports are machine-global").
    dynamic_port_range: [30000, 40000]
    dynamic_port_count: 10
    mounts:
      - {source: /home/me/repo, target: /root/workspace, mode: rw}
    # Secrets are references, never values: smolvm resolves each one on the
    # host at machine start and puts it in the guest environment.
    secrets:
      - {env_var: GH_TOKEN, keychain: omnigent/github}
    ssh_agent: false
    agent_workspace: true
    agent_workspace_root: /home/me/agent_work
```

## Secrets

Nothing secret is held by this provider. Each `secrets:` entry names where the
value lives and the provider writes only that reference to `machine create`:

| Config | Flag | Where the value lives |
|---|---|---|
| `{env_var: X, keychain: service/account}` | `--secret-keychain X=service/account` | host keychain (`secret-tool` on Linux) |
| `{env_var: X, env: HOST_VAR}` | `--secret-env X=HOST_VAR` | this host's environment |
| `{env_var: X, file: /abs/path}` | `--secret-file X=/abs/path` | a host file |

smolvm resolves them at every machine start, so a rotated value takes effect
on the next start, not on the next `exec`. A missing keychain item fails the
start with `keychain_item_missing`.

### Brokered credentials

`credentials:` keeps a secret out of the guest entirely. smolvm terminates TLS
for the listed hosts on the host side, substitutes the real value into a header,
and refuses it anywhere else; the guest holds an opaque placeholder.

```yaml
    allow_host_patterns: ["*.atlassian.com"]
    credentials:
      - name: jira
        env_var: JIRA_TOKEN
        hosts: ["api.atlassian.com"]
        keychain: omnigent/jira   # or env:/file:; omit to read the host var
        set_header: Authorization # optional: set the header outright
```

The host must also be reachable by the machine's egress policy — smolvm refuses
the launch otherwise, and the config validator says so before it gets that far.

### SSH agent

`ssh_agent: true` forwards the host's agent into the guest, so `git` and `ssh`
use the host keys without copying them in. The host needs `SSH_AUTH_SOCK` set
when the machine is created.

## Ports are machine-global

`ports:` publishes host ports, and a host port belongs to whichever machine
holds it. Starting a second machine on one already in use fails:

```text
config operation failed: start machine: host port 8080 is already in use by
running machine 'omni-managed-…' (CONFIG_ERROR)
```

So a shared profile should not declare ports — otherwise its sandboxes exclude
each other, which only shows up when the second one launches. Give the
sandboxes that need a listener their own alias, and let the plain profile run
with none:

```yaml
- provider: smolvm-ui
  server_url: http://100.96.0.1:6767
  smolvm-ui:
    image: /home/me/.omnigent/sandbox/smolvm/omnigent-host-fedora-1.tar
    net_backend: virtio-net
    ports: ["8081:8080"]      # one at a time, by design
```

smolvm cannot allocate a host port on its own (`-p 0:8080` is rejected), so a
port has to be chosen when the machine is created — which is what
`dynamic_port_range` is for. Ask for a count and a range and the provider
picks, per session:

```yaml
    dynamic_port_range: [30000, 40000]
    dynamic_port_count: 10
```

At provision time it takes a host-wide lock, reads the ports every other
managed machine already holds (the `omnigent.ports` label plus
`published_ports` from `machine ls --json`), takes the lowest free ones and
passes each as `--port N:N`, so the host port and the guest port are the same
number. Concurrent sandboxes get disjoint slices; a range that cannot cover the
request fails with `only N of M free host ports …` before anything is created.
The two settings must be given together, and fixed plus dynamic mappings may
not exceed smolvm's 64.

The allocation is written to the machine's labels, to `<workspace>/sandbox-info.md`
on the host, and to `/root/sandbox-info.md` in the guest — together with the
provider, image, host gateway, work directory and the egress rules the machine
actually got. Agents are pointed at that file, so they learn which host ports
are theirs instead of guessing.

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

`smolvm` also supports mediated egress (`--mediated-egress` with an
`--egress-interceptor` decider), checkpoints, branching, and named inter-VM
networks. This provider does not use them; the profile schema is intentionally
small and validators reject anything it cannot honour.
