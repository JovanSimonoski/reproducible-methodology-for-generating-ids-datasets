# attacklog

This component accompanies the master thesis **A Reproducible Methodology for Generating Modern Intrusion Detection Datasets** by Jovan Simonoski. It is maintained in the [unified thesis repository](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets).

A lightweight CLI tool for tracking cybersecurity attack attempts in a controlled research environment. Records structured attack metadata to a local SQLite database for later use in automatic labeling of network flows and packet captures.

---

## Table of Contents

- [attacklog](#attacklog)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Setup](#setup)
    - [Requirements](#requirements)
    - [Installation](#installation)
    - [Initialization](#initialization)
  - [Commands](#commands)
    - [init](#init)
    - [start](#start)
      - [dst-ip formats](#dst-ip-formats)
      - [dst-port formats](#dst-port-formats)
    - [end](#end)
    - [list](#list)
    - [export](#export)
  - [Attack Types](#attack-types)
  - [Workflow](#workflow)
  - [Data Storage](#data-storage)
    - [Database schema](#database-schema)

---

## Overview

Each attacker runs `attacklog` to bracket every attack with a **start** and **end** event. This produces one structured record per attack containing the attacker identity, target, timestamps, and outcome. These records are later joined against NetFlow and raw packet captures to produce labeled dataset entries.

**Key properties:**
- No external dependencies - pure Python standard library
- Millisecond-precision UTC timestamps from the system clock
- Enforces one open attack at a time (prevents unlabeled gaps)
- Supports single targets, port scans, and network scans

---

## Setup

### Requirements

- Python 3.10+

### Installation

```bash
# From the unified repository root:
cd attacklog
chmod +x attacklog.py
sudo cp attacklog.py /usr/local/bin/attacklog
```

### Initialization

Must be run once per machine before any other command:

```bash
attacklog init --attacker-id <id> --src-ip <ip>
```

This writes the attacker identity to `~/.attacklog/config.json` and creates the SQLite database at `~/.attacklog/attacks.db`.

---

## Commands

### init

Initialize attacklog on this machine. Run once at setup.

```
attacklog init --attacker-id <id> --src-ip <ip>
```

| Option | Required | Description |
|---|---|---|
| `--attacker-id` | Yes | Unique attacker identifier (e.g. `attacker_1`) |
| `--src-ip` | Yes | The attacker machine's static VPN IP address |

**Example:**
```bash
attacklog init --attacker-id attacker_3 --src-ip 10.10.20.3
```

---

### start

Record the beginning of an attack. Refuses to run if another attack is already open.

```
attacklog start --name <name> --dst-ip <ip> --dst-port <port> [--protocol <proto>]
```

| Option | Required | Default | Description |
|---|---|---|---|
| `--name` | Yes | - | Canonical attack name (e.g. `ms3-jenkins-revshell`) |
| `--dst-ip` | Yes | - | Target IP - single address, CIDR block, or range (see [formats](#dst-ip-formats)) |
| `--dst-port` | Yes | - | Target port - single, range, or comma-separated list (see [formats](#dst-port-formats)) |
| `--protocol` | No | `tcp` | Protocol: `tcp`, `udp`, or `icmp` |

**Examples:**
```bash
# Targeted attack
attacklog start --name ms3-jenkins-revshell --dst-ip 10.10.10.16 --dst-port 8484

# Port scan (single host, many ports)
attacklog start --name nmap-port-scan --dst-ip 10.10.10.16 --dst-port 1-1024

# Network scan (many hosts, many ports)
attacklog start --name nmap-network-scan --dst-ip 10.10.10.0/24 --dst-port 22,80,443

# UDP attack
attacklog start --name ms3-snmp-enum --dst-ip 10.10.10.16 --dst-port 161 --protocol udp
```

#### dst-ip formats

| Format | Example | Description |
|---|---|---|
| Single address | `10.10.10.16` | One target host |
| CIDR block | `10.10.10.0/24` | Subnet |
| Range | `10.10.10.1-10.10.10.254` | Inclusive address range |

#### dst-port formats

| Format | Example | Description |
|---|---|---|
| Single port | `8484` | One target port |
| Range | `1-1024` | Contiguous port range |
| List | `22,80,443` | Specific ports |

---

### end

Close the most recently started open attack and record its outcome.

```
attacklog end --status <status> [--notes <text>]
```

| Option | Required | Description |
|---|---|---|
| `--status` | Yes | Outcome of the attack (see values below) |
| `--notes` | No | Free-text field for anything unusual |

**Status values:**

| Value | Meaning |
|---|---|
| `success` | Attack executed and exploited successfully |
| `ran` | Attack ran without errors but did not exploit (also used for scans) |
| `error` | Tool errored or attack failed to run properly |

**Examples:**
```bash
attacklog end --status success
attacklog end --status ran
attacklog end --status error --notes "Module failed to connect, retried once"
```

---

### list

Display recorded attacks as a formatted table, most recent first.

```
attacklog list [--limit <n>]
```

| Option | Required | Default | Description |
|---|---|---|---|
| `--limit` | No | All | Number of most recent records to show |

**Examples:**
```bash
attacklog list
attacklog list --limit 5
```

---

### export

Export all records to JSON or CSV.

```
attacklog export [--format <fmt>] [--output <file>]
```

| Option | Required | Default | Description |
|---|---|---|---|
| `--format` | No | `json` | Output format: `json` or `csv` |
| `--output` | No | stdout | File path to write to |

**Examples:**
```bash
# Print JSON to stdout
attacklog export

# Save as CSV
attacklog export --format csv --output attacks.csv

# Save as JSON
attacklog export --format json --output attacks.json
```

---

## Attack Types

The attack type is inferred automatically from the `--dst-ip` and `--dst-port` values provided at `start`. It is stored in the database and included in exports.

| Type | dst-ip | dst-port |
|---|---|---|
| `targeted` | Single address | Single port |
| `port_scan` | Single address | Range or list |
| `network_scan` | CIDR or range | Any |

---

## Workflow

The standard per-attack workflow:

```
1. attacklog start --name <attack_name> --dst-ip <ip> --dst-port <port>
2. ... run the attack ...
3. attacklog end --status <success|ran|error>
```

**Important:** `start` will refuse to run if a previous attack has no `end` recorded. Always close the current attack before starting a new one.

---

## Data Storage

| Path | Description |
|---|---|
| `~/.attacklog/config.json` | Attacker identity (`attacker_id`, `src_ip`) - written once at `init` |
| `~/.attacklog/attacks.db` | SQLite database containing all attack records |

### Database schema

| Column | Type | Description |
|---|---|---|
| `attack_id` | TEXT | UUID - auto-generated per attempt |
| `attacker_id` | TEXT | From config |
| `src_ip` | TEXT | From config |
| `dst_ip` | TEXT | Normalised target IP / range / CIDR |
| `dst_port` | TEXT | Normalised target port / range / list |
| `protocol` | TEXT | `tcp`, `udp`, or `icmp` |
| `attack_name` | TEXT | Canonical name provided at `start` |
| `attack_type` | TEXT | Inferred: `targeted`, `port_scan`, or `network_scan` |
| `t_start` | TEXT | ISO 8601 UTC timestamp with millisecond precision |
| `t_end` | TEXT | ISO 8601 UTC timestamp with millisecond precision (null if open) |
| `status` | TEXT | `success`, `ran`, or `error` (null if open) |
| `notes` | TEXT | Optional free-text notes |
