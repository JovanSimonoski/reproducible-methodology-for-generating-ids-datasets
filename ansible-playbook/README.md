# Laboratory Preparation and Log Shipping

This component accompanies the master thesis **A Reproducible Methodology for Generating Modern Intrusion Detection Datasets** by Jovan Simonoski. It is maintained in the [unified thesis repository](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets).

Automation for three fleets of lab VMs on vSphere/vCenter, configuring
single-NIC networking, unique hostnames, time sync against the university NTP
server, and log shipping to a central VictoriaLogs instance. The end goal is
**automatically labeled, time-synced logs** (and packet captures) that can be
correlated across all machines.

## Fleets

| Fleet | OS | Count | Notes |
|-------|----|-------|-------|
| **vulhub** | Ubuntu Server 24.04 | 14 | Modern stack: netplan, systemd, Promtail, timesyncd |
| **metasploitable2** | Ubuntu 8.04 (Hardy) | 7 | Ancient: Python 2.5, SysVinit, 32-bit — all playbooks `raw`-only |
| **metasploitable3** | Windows Server 2008 R2 | 7 | WinRM/NTLM, PowerShell 2.0, W32Time, homegrown PS shipper |

## Network architecture (2026-07 revision: SINGLE NIC)

All fleets use **one NIC** on the management VLAN. The former second
(internet) NIC is disconnected/removed in vCenter — see history below.

- **Management NIC** — static or DHCP `192.168.77.x`; Ansible connects over
  it, and it owns the **default route via `192.168.77.1`**, which carries
  everything (internal lab subnets + the only allowed external egress).
- **Egress policy**: only the FINKI NTP server (`ntp.finki.ukim.mk` =
  `194.149.136.252`, UDP 123) is reachable beyond the lab. **No general
  internet** — no apt, no downloads; anything the VMs need must be pushed
  via Ansible (`win_copy` / base64-over-`raw`).
- **DNS**: the gateway `192.168.77.1` serves DNS (search domain
  `lab138.finki.ukim.mk`) and resolves external names like the NTP host.

Internal subnets (all directly reachable via the default route):
- `192.168.77.0/24` — management subnet
- `192.168.71.0/24` — VPN / control-path (WSL control node)
- `192.168.85.0/24` — VictoriaLogs server (`192.168.85.125:9428`)

### History (why the playbooks read the way they do)

The lab was originally dual-homed: management NIC with no default route +
an internet NIC (DHCP on `10.10.x`) owning the default. The `10.10.x` NAT
**dropped NTP traffic sourced from UDP port 123**, which broke every native
NTP daemon (W32Time and ntpd hardcode source port 123) while `ntpdate -u` /
`w32tm /stripchart` (high source ports) worked — the origin of several
workarounds since removed. Internet access was later enabled on (and then
restricted to NTP-only through) `192.168.77.1`, the second NICs were
disconnected, and everything was re-pointed at the single gateway.

## Directory layout

```
ansible-playbook/
├── ansible.cfg
├── inventory.ini                    # [vulhub], [metasploitable2], [metasploitable3]
├── README.md                        # this file
│
├── vulhub/                          # Ubuntu 24.04
│   ├── configure-netplan.yml        # SINGLE-NIC routing (auto-detects mgmt NIC)
│   ├── set-hostnames.yml            # unique hostnames from inventory names
│   ├── vmware-logs.yml              # Promtail log shipping + NTP (timesyncd)
│   ├── verify-logging.yml           # READ-ONLY health check (shipping + NTP + DNS)
│   ├── templates/netplan-single-nic.yaml.j2
│   ├── promtail/{config.yaml.j2,promtail.service.j2}
│   └── files/promtail-linux-amd64{,.zip}
│
├── metasploitable2/                 # Ubuntu 8.04 (raw-only)
│   ├── configure-network.yml        # SINGLE-NIC routing (/etc/network/interfaces)
│   ├── set-hostnames.yml            # unique hostnames
│   ├── configure-ntp.yml            # precision ntpdate loop (4x/min, slewing)
│   ├── ship-logs.yml                # curl shipper -> VictoriaLogs 9428
│   └── files/{vlogs-shipper.sh,vlogs-shipper-init.sh}
│
└── metasploitable3/                 # Windows Server 2008 R2 (WinRM)
    ├── configure-ntp.yml            # default route via 192.168.77.1 + native W32Time
    ├── set-hostname.yml             # unique hostnames
    ├── ship-logs.yml                # PowerShell Event Log shipper -> VictoriaLogs
    └── files/vlogs-shipper.ps1
```

Paths inside playbooks are relative to the playbook, so `templates/`,
`promtail/`, and `files/` must sit next to their playbook. Run everything from
the project root with the folder prefix.

---

## Prerequisites

### vSphere (manual — cannot be done by these playbooks)

- Every VM: exactly ONE connected network adapter, on the management VLAN
  port group. **Disconnect (or better, remove) any second adapter** — a
  still-connected legacy NIC re-acquires a DHCP lease and injects a
  competing, lower-metric default route via the dead `10.10.x` path, which
  silently breaks both NTP and log shipping (observed on metas3-7).
  metasploitable2 NICs must be **E1000** (the 8.04 kernel has no vmxnet3
  driver); power-cycle after NIC changes (8.04 does not hotplug PCI).
- **Snapshot reverts undo everything** these playbooks configure (routes,
  cron/tasks, shippers). After reverting a VM, re-run its fleet's playbooks
  scoped to that host (`--limit`). All playbooks are idempotent.
- VMware Tools time sync should be OFF for the Windows fleet (checkbox +
  the `time.synchronize.*` advanced parameters) so it doesn't fight W32Time.
- Gateway `192.168.77.1` must: route the internal subnets, serve DNS,
  and permit UDP 123 (both high-source and source-port-123) to
  `194.149.136.252`.
- VictoriaLogs running and reachable at `192.168.85.125:9428` (HTTP
  ingestion + UI). No syslog listener needed — all three fleets ship HTTP.

### Control node (WSL)

```bash
sudo apt update && sudo apt install -y ansible sshpass
# WinRM support for the metasploitable3 fleet:
pip install pywinrm
```

Keep the project in the WSL Linux filesystem (e.g. `~/reproducible-methodology-for-generating-ids-datasets/ansible-playbook`), NOT
under `/mnt/c/...` — Windows-mounted dirs show as world-writable and Ansible
refuses to load `ansible.cfg` from them.

For manual SSH to metasploitable2 boxes, modern OpenSSH needs legacy options
(`~/.ssh/config` on the control node):

```
Host metas2-* 192.168.77.*
    HostKeyAlgorithms +ssh-rsa,ssh-dss
    PubkeyAcceptedKeyTypes +ssh-rsa
    KexAlgorithms +diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```

### inventory.ini

```ini
[vulhub]
vulhub-1-1 ansible_host=192.168.77.235
# ... 14 hosts ...

[vulhub:vars]
ansible_user=vulhub-ubuntu-server
ansible_password=vulhub
ansible_become_pass=vulhub

[metasploitable2]
metas2-1 ansible_host=192.168.77.249
# ... 7 hosts ...

[metasploitable2:vars]
ansible_user=msfadmin
ansible_password=msfadmin
ansible_become_pass=msfadmin
ansible_ssh_common_args=-oHostKeyAlgorithms=+ssh-rsa,ssh-dss -oPubkeyAcceptedKeyTypes=+ssh-rsa

[metasploitable3]
metas3-1 ansible_host=192.168.77.244
# ... 7 hosts ...

[metasploitable3:vars]
ansible_user=vagrant
ansible_password=vagrant
ansible_connection=winrm
ansible_port=5985
ansible_winrm_transport=ntlm
ansible_winrm_scheme=http
```

### ansible.cfg

```ini
[defaults]
inventory = inventory.ini
host_key_checking = False
```

---

## Run order

Within each fleet: **network → hostnames → NTP → logs**. Network first
(everything needs the route to NTP and VictoriaLogs); hostnames before logs
(so logs are labeled); NTP before relying on timestamps. Fleets are
independent of each other. For metasploitable3, network and NTP are one
playbook.

Test each step on one host (`--limit`) before the whole fleet.

### 0. Connectivity check

```bash
cd ~/reproducible-methodology-for-generating-ids-datasets/ansible-playbook
ansible vulhub -m ping
ansible metasploitable2 -m raw -a "hostname"
ansible metasploitable3 -m ansible.windows.win_shell -a "hostname"
```

### vulhub (Ubuntu 24.04)

```bash
# 1. Network (single NIC, default via 192.168.77.1; netplan try auto-reverts)
ansible-playbook vulhub/configure-netplan.yml --limit vulhub-1-1
ansible-playbook vulhub/configure-netplan.yml

# 2. Hostnames
ansible-playbook vulhub/set-hostnames.yml

# 3. Promtail + NTP (timesyncd -> ntp.finki.ukim.mk)
ansible-playbook vulhub/vmware-logs.yml --limit vulhub-1-1
ansible-playbook vulhub/vmware-logs.yml

# 4. Health check (read-only, any time)
ansible-playbook vulhub/verify-logging.yml
```

### metasploitable2 (Ubuntu 8.04) — keep a vCenter console open for step 1

```bash
# 1. Network (no auto-revert on this OS — console open as a safety net)
ansible-playbook metasploitable2/configure-network.yml --limit metas2-1
ansible-playbook metasploitable2/configure-network.yml

# 2. Hostnames
ansible-playbook metasploitable2/set-hostnames.yml

# 3. NTP (fixes resolv.conf, installs the 4x/min ntpdate slew loop)
ansible-playbook metasploitable2/configure-ntp.yml --limit metas2-1
ansible-playbook metasploitable2/configure-ntp.yml

# 4. Log shipping (rev-2 curl shipper -> VictoriaLogs 9428)
ansible-playbook metasploitable2/ship-logs.yml --limit metas2-1
ansible-playbook metasploitable2/ship-logs.yml
```

### metasploitable3 (Server 2008 R2)

```bash
# 1. Network + NTP in one play: persistent default route via 192.168.77.1,
#    removes the legacy stripchart workaround, configures native W32Time,
#    verifies sync end-to-end (retries until Source = ntp.finki.ukim.mk)
ansible-playbook metasploitable3/configure-ntp.yml --limit metas3-1
ansible-playbook metasploitable3/configure-ntp.yml

# 2. Hostnames
ansible-playbook metasploitable3/set-hostname.yml

# 3. Log shipping (PowerShell Event Log shipper, per-minute scheduled task)
ansible-playbook metasploitable3/ship-logs.yml --limit metas3-1
ansible-playbook metasploitable3/ship-logs.yml
```

---

## Verification

### Routing (all fleets — expect exactly ONE default, via 192.168.77.1)

```bash
ansible vulhub -m command -a "ip route get 194.149.136.252" --become
ansible metasploitable2 -m raw -a "ip route" --become
ansible metasploitable3 -m ansible.windows.win_shell -a "route print -4 | findstr /C:\"0.0.0.0\""
```

A SECOND `0.0.0.0` line on a Windows host (or a `10.10.x` gateway anywhere)
means a legacy NIC is still connected in vCenter — fix there, not in the OS.

### NTP

```bash
ansible vulhub -m command -a "timedatectl show -p NTPSynchronized" --become
# metas2: healthy = recent 'adjust' lines; recurring 'step' = VM clock problem
ansible metasploitable2 -m raw -a "grep ntpdate /var/log/syslog | tail -2" --become
# metas3: Source must be ntp.finki.ukim.mk, NOT 'Local CMOS Clock'
ansible metasploitable3 -m ansible.windows.win_shell -a "w32tm /query /status | findstr /C:\"Source\""
```

### Log shipping

```bash
ansible-playbook vulhub/verify-logging.yml
ansible metasploitable2 -m raw -a "pgrep -f vlogs-shipper >/dev/null && echo shipping || echo DOWN" --become
ansible metasploitable3 -m ansible.windows.win_shell -a "Get-Content C:\\ProgramData\\vlogs-shipper\\shipper.log -Tail 3"
```

### End-to-end

In the VictoriaLogs UI, the `hostname` field should list all 28 machines
(`vulhub-*`, `metas2-*`, `metas3-*`) with fresh entries. The m3 shipping
playbook also injects a searchable marker: `vlogs shipper test marker`.

---

## Time sync design (per fleet)

| Fleet | Mechanism | Expected precision |
|-------|-----------|--------------------|
| vulhub | systemd-timesyncd -> `ntp.finki.ukim.mk` | ms-level, disciplined |
| metasploitable2 | `ntpdate -u -p 8` loop, 4x/min via cron script; slews (<0.5s offsets), steps only if grossly off | ~1-5 ms steady state |
| metasploitable3 | native W32Time, manual peer `0x9`, hourly poll (`SpecialPollInterval=3600`), phase correction capped at 48h | tens of ms between polls |

metasploitable2 details: no NTP daemon exists on the image and none can be
installed (egress blocked). `/usr/local/sbin/ntp-sync-loop.sh` (deployed by
`configure-ntp.yml`) runs 4 syncs/min; residual error is inter-sync frequency
drift, which only a daemon could remove. If tighter cross-fleet correlation is
ever needed, the first lever is shortening the Windows poll interval.

metasploitable3 details: W32Time syncs natively now that its (hardcoded)
source-port-123 traffic goes via `192.168.77.1`. Never use
`w32tm /resync /rediscover` when debugging — it discards the pending sample
and restarts the (15-20s) poll, creating an endless "no time data was
available" loop. Plain `w32tm /resync` only.

---

## Log shipping design (per fleet)

### vulhub — Promtail
Tails `/var/log/{*.log,syslog}` and pushes to VictoriaLogs' Loki-compatible
endpoint. Positions file gives no-loss/no-dup delivery. (Known mild
duplication: `kern.log` lines also appear in `syslog`; acceptable.)

### metasploitable2 — sh/tail/perl/curl shipper (rev 2)
Promtail is impossible (32-bit i686, ancient glibc/kernel). The shipper tails
**only** `/var/log/syslog` + `/var/log/auth.log` — on 8.04 sysklogd these are
disjoint; `daemon.log`/`messages` are subsets of syslog and shipping them
duplicated most lines (do not add them back). `tail -n 0` prevents re-shipping
on restart; tail's multi-file `==> path <==` headers are parsed into a `file`
stream field; a noise regex drops ntpdate-success and sync-cron lines
(failures still ship); lines POST in batches (<=100 lines / 2s) with one
retry. Trade-offs: no durable queue (a batch failing twice is dropped; lines
written while the shipper is down are never shipped). Deployed via base64
over `raw` to survive SSH quoting.

### metasploitable3 — PowerShell 2.0 Event Log shipper
Ships System, Application, and Security channels. Per-minute scheduled task
as SYSTEM (Security needs it), mutex-guarded, single pass per run. Positions
= Event Log **record IDs**, stored in
`C:\ProgramData\vlogs-shipper\positions.txt` and advanced only after a
successful POST -> no duplicates on restart AND no loss during VictoriaLogs
downtime (backlog drains at 1000 events/channel/min). Timestamps are the
events' own `TimeCreated` (UTC). First run initializes positions to the
current tail (no history import); to backfill a host, lower its record ID in
positions.txt. `$ExcludeEventIds` in the script filters flooding IDs (empty
by default). PS 2.0 constraints honored: no JSON cmdlets, `WebClient` for
HTTP, en-US culture pin for event message formatting.

---

## Design notes & gotchas (hard-won — read before "improving" anything)

- **metasploitable2 is `raw`-only.** Python 2.5 predates Ansible's module
  requirements; all plays use `raw`, `gather_facts: false`, native
  `become: true` (which crucially does not consume stdin, so heredocs work).
- **`pkill -f` self-match:** a raw task's wrapper shell contains the pattern
  text on its own command line, so `pkill -f 'dhclient.*eth1'` kills its own
  SSH session (host shows UNREACHABLE mid-play; the host is fine). Always use
  the bracket trick: `pkill -f '[d]hclient.*eth1'`.
- **8.04 resolv.conf goes stale:** the removed internet NIC's DHCP had
  written its `10.10.x` nameserver into `/etc/resolv.conf`; static eth0
  maintains nothing, so DNS silently died with the NIC.
  `metasploitable2/configure-ntp.yml` pins `nameserver 192.168.77.1`.
- **netplan needs a second `apply`:** on the vulhub images, one
  `netplan try`/`apply` can leave new static routes uninstalled (observed:
  no default route until a second `netplan apply`). The playbook includes the
  nudge — do not remove it (again).
- **netplan doesn't flush removed interfaces:** an interface dropped from the
  config keeps its addresses/routes until reboot; the playbook flushes the
  legacy NIC explicitly.
- **Windows dual-default-route trap:** persistent routes cannot defend
  against a still-connected legacy NIC — its DHCP renewal re-adds a
  lower-metric default (`10.10.16.253`) that wins, breaking NTP + shipping
  while WinRM (directly connected subnet) still works. Root fix is in
  vCenter: disconnect/remove the adapter.
- **W32Time vs stripchart asymmetry:** `w32tm /stripchart` uses a high source
  port and can succeed while the W32Time *service* (hardcoded source port
  123) fails — never conclude "network is fine" from stripchart alone.
- **"UNREACHABLE" on raw-only hosts** can mean the task killed its own
  shell/session, not that the host died. Check the host before panicking.
- **Ansible "Sample Prepared" / w32tm debug logs:** empty samples show
  `Ofs:+00.0000000s Dsp:16.0000000s` — that is a placeholder, not data.
- **No internet egress:** apt/downloads are impossible on the VMs. Old
  references to repointing apt at `old-releases.ubuntu.com` are obsolete.
  Push binaries via Ansible (promtail is copied from `files/`; the shippers
  are plain scripts).

## Idempotency & safety

- All playbooks are safe to re-run and safe to run after snapshot reverts.
- vulhub network changes use `netplan try` (auto-revert in 120s if
  connectivity drops) + `serial: 1`. metasploitable2 has NO auto-revert —
  keep a vCenter console open for network plays. metasploitable3 route
  changes are safe over WinRM (controller is on the directly-connected
  management subnet).
- Failed VictoriaLogs preflights abort shipping deployment per-host by
  design — a preflight failure means a routing/vCenter problem to fix first.
- After any reboot, verify persistence on one host per fleet: route holds,
  time syncs, shipper resumes (m2: init script via `update-rc.d`; m3:
  scheduled task; vulhub: systemd units).
