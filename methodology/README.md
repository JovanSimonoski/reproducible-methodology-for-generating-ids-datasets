# A Reproducible Methodology for Generating Modern Intrusion Detection Datasets

A complete methodology for building a labeled network attack dataset in a controlled environment, suitable for IDS/IPS systems and ML research.

This project accompanies the master thesis **A Reproducible Methodology for Generating Modern Intrusion Detection Datasets** by Jovan Simonoski. The implementation components are maintained in the [unified thesis repository](https://github.com/JovanSimonoski/reproducible-methodology-for-generating-ids-datasets).

---

## What This Is

This repository defines the end-to-end process for:

1. Setting up an isolated attack environment with vulnerable machines
2. Coordinating volunteer attackers executing reproducible, documented attacks
3. Monitoring and capturing network traffic (raw packets + NetFlow)
4. Automatically labeling captured data using timestamps from each attack session

The resulting dataset can be used for training and evaluating IDS/IPS systems, ML classifiers, and anomaly detection models.

---

## Environment Design

| Component | Details |
|---|---|
| Vulnerable VMs | Metasploitable 2 (Linux), Metasploitable 3 (Windows) |
| Docker targets | VulHub containers - recent CVEs |
| Attacker VMs | Preconfigured Kali Linux (one per attacker) |
| Log stack | Kafka → VictoriaLogs (via Promtail / Fluentbit) |
| Flow data | nProbe (NetFlow probe) → ntopng → Kafka |
| Time sync | NTP via `ntp.finki.ukim.mk` on all machines |

---

## Attack Catalog

26 attacks documented with step-by-step instructions, specific commands, and attack variations. Each attack has a canonical name used for labeling.

### Metasploitable 2
- Unix R-Services Reverse Shell
- UnrealIRCd Backdoor Reverse Shell
- DVWA: XSS Reflected, XSS Stored, Command Injection, LFI, SQL Injection
- Mutillidae: SQLMap (multiple techniques - boolean, time-based, error-based, UNION)

### Metasploitable 3
- GlassFish / Jenkins Reverse Shells
- IIS HTTP DoS (CVE-2015-1635)
- IIS FTP Wordlist Brute Force
- ElasticSearch RCE (CVE-2014-3120)
- SNMP Enumeration
- JMX RCE (CVE-2015-2342)

### VulHub (Docker - recent CVEs)
- Flask Jinja2 SSTI
- Apache Airflow: CVE-2020-11978, CVE-2020-11981, CVE-2020-17526
- 1Panel SQL Injection (CVE-2024-39907)
- Apache ActiveMQ RCE: CVE-2022-41678, CVE-2026-34197
- AJ-Report Auth Bypass + RCE (CNVD-2024-15077)
- Apache CXF SSRF (CVE-2024-28752)
- Apache Druid JS RCE (CVE-2021-25646)
- Apache APISIX Hardcoded Token RCE (CVE-2020-13945)

Full instructions: [Methodology.md](Methodology.md)

---

## Automatic Labeling

The core contribution of this methodology is a reliable automatic labeling process that requires no manual annotation of network flows.

Each attacker uses [`attacklog`](../attacklog/README.md) - a custom CLI tool - to bracket every attack with a start and end event. This produces one structured SQLite record per attack attempt, capturing:

- Attacker identity and source IP
- Attack name, destination IP, port, protocol
- Millisecond-precision UTC timestamps (`t_start` / `t_end`)
- Outcome: `success`, `ran`, or `error`

Post-processing joins these records against NetFlow and PCAP data:
- **Join key:** `src_ip + dst_ip + dst_port + protocol`
- **Time window:** `t_start / t_end` with ±1s tolerance for clock jitter

Any flow outside a matched window is labeled **benign** - safe to assume given the fully isolated environment with no legitimate user traffic on target services.

---

## Attacker Workflow

```
attacklog start --name <attack_name> --dst-ip <ip> --dst-port <port>
# ... execute the attack ...
attacklog end --status <success|ran|error>
```

`attacklog` enforces that no new attack starts until the previous one is closed, ensuring clean timestamp boundaries.

---

## Attack Outcomes

| Status | Meaning |
|---|---|
| `success` | Exploited successfully |
| `ran` | Ran without errors, did not exploit (also used for scanning) |
| `error` | Tool errored / attack did not run properly |
