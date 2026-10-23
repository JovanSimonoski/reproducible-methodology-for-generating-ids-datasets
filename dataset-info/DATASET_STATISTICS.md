# cyber-attacks-dataset — Statistics

Generated 2026-10-23 15:37 UTC by `analyze_dataset.py` from `cyber_attacks_flows_labeled.csv` (dataset built 2026-10-23 15:36 UTC). Every number below is computed from the data and its provenance files. Times are UTC. Percentages are of all flows unless a column says otherwise.

**Contents:** [1. At a glance](#1-at-a-glance) · [2. Captures](#2-captures) · [3. Labels and class balance](#3-labels-and-class-balance) · [4. Traffic profile per class](#4-traffic-profile-per-class) · [5. Attack records, attackers and targets](#5-attack-records-attackers-and-targets) · [6. Flow characteristics](#6-flow-characteristics) · [7. Protocols and applications](#7-protocols-and-applications) · [8. Ports](#8-ports) · [9. Hosts and network](#9-hosts-and-network) · [10. Time](#10-time) · [11. Data quality and integrity](#11-data-quality-and-integrity) · [12. Features (columns)](#12-features-columns) · [13. Provenance and configuration](#13-provenance-and-configuration)

## 1. At a glance

| Metric | Value |
| :--- | :--- |
| Flows (rows) | 2,263,421 |
| Attack flows | 1,798,765 (79.47%) |
| Benign flows | 464,656 (20.53%) |
| Classes | 54 (53 attack classes + BENIGN) |
| Captures | 2 (07, 10) |
| Traffic time covered | 15.40 days (07: 3.04 d, 10: 12.36 d) |
| Packets in flows | 10,078,839 (59.61% in attack flows) |
| Bytes in flows (L2 frames) | 2.33 GB (79.70% in attack flows) |
| Unique IP addresses | 148 |
| Attackers (source IPs) | 6 |
| Target hosts | 20 |
| Logged attack records (attacklog) | 267 (07: 229, 10: 38) |
| Raw capture | 2,220 pcap files, 2.55 GB, 10,863,227 frames |
| Columns | 186 flow columns + `capture_id` + `label` = 188 |
| Files | `cyber_attacks_flows.csv` 2.58 GB, `cyber_attacks_flows_labeled.csv` 2.62 GB |

## 2. Captures

| Metric | Capture 07 | Capture 10 | Total |
| :--- | ---: | ---: | ---: |
| Traffic window start | 2026-07-14 07:45 | 2026-10-01 00:00 |  |
| Traffic window end | 2026-07-17 08:43 | 2026-10-13 08:41 |  |
| Duration | 3.04 d | 12.36 d | 15.40 d |
| Pcap files (10-min rotation) | 439 | 1,781 | 2,220 |
| Pcap size | 2.12 GB | 430.37 MB | 2.55 GB |
| Frames captured | 8,534,197 | 2,329,030 | 10,863,227 |
| IP packets in flows | 8,298,630 | 1,780,209 | 10,078,839 |
| Frames in no flow (non-IP L2: STP, ARP, …) | 235,567 (2.76%) | 548,821 (23.56%) | 784,388 |
| Flows | 1,796,455 | 466,966 | 2,263,421 |
| Share of dataset | 79.37% | 20.63% | 100% |
| Attack flows | 1,413,666 (78.69%) | 385,099 (82.47%) | 1,798,765 (79.47%) |
| Benign flows | 382,789 (21.31%) | 81,867 (17.53%) | 464,656 (20.53%) |
| Packets in flows | 8,298,630 | 1,780,209 | 10,078,839 |
| …of which in attack flows | 58.77% | 63.49% | 59.61% |
| Bytes in flows | 1.97 GB | 355.83 MB | 2.33 GB |
| …of which in attack flows | 79.43% | 81.19% | 79.70% |
| Average flows per hour | 24,620 | 1,573 | 6,122 |
| Attackers | 4 | 2 | 6 |
| Target hosts | 15 | 5 | 20 |
| Logged attack records | 229 | 38 | 267 |
| Attack classes present | 53 | 29 | 53 |
| Unique IP addresses | 112 | 99 | 148 |
| Stitched flows (split by file rotation, repaired) | 1,589 | 833 | 2,422 |
| Flows cut at capture edges | 361 | 5 | 366 |

All traffic was captured on a single VLAN (id 1017). The captures were processed with the identical extraction and identical labeling settings (section 13). Frames in no flow are layer-2 frames without an IP header (spanning tree, ARP, …); NFStream builds flows from IP packets only, so their share is highest in captures with little IP traffic.

## 3. Labels and class balance

### 3.1 Attack vs benign

| Capture | Flows | Attack | Attack % | Benign | Benign % | Attack : benign |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| 07 | 1,796,455 | 1,413,666 | 78.69% | 382,789 | 21.31% | 1 : 0.271 |
| 10 | 466,966 | 385,099 | 82.47% | 81,867 | 17.53% | 1 : 0.213 |
| **Total** | 2,263,421 | 1,798,765 | 79.47% | 464,656 | 20.53% | 1 : 0.258 |

### 3.2 By attack technique

Technique is derived from the canonical attack name. `-portscan` classes are the single-port service scan each attacker ran right before the matching exploit.

| Technique | Classes | Flows | % of all | % of attacks | Packets | Bytes |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Port scan (full TCP range) | 1 | 1,728,220 | 76.35% | 96.08% | 3,451,920 | 220.94 MB |
| Benign | 1 | 464,656 | 20.53% | – | 4,071,118 | 472.50 MB |
| SQL injection | 2 | 53,363 | 2.36% | 2.97% | 2,278,327 | 1.56 GB |
| Brute force (wordlist) | 1 | 15,924 | 0.70% | 0.89% | 203,159 | 16.15 MB |
| Known-vulnerability exploit (CVE/CNVD) | 10 | 601 | 0.03% | 0.03% | 24,561 | 18.73 MB |
| Remote code execution (reverse shell) | 6 | 367 | 0.02% | 0.02% | 30,381 | 23.34 MB |
| Service scan (single port, pre-exploit) | 26 | 131 | <0.01% | <0.01% | 1,221 | 154.19 KB |
| Cross-site scripting | 2 | 70 | <0.01% | <0.01% | 2,165 | 1.05 MB |
| Denial of service | 1 | 53 | <0.01% | <0.01% | 11,046 | 11.20 MB |
| OS command injection | 1 | 13 | <0.01% | <0.01% | 550 | 306.33 KB |
| Server-side template injection | 1 | 12 | <0.01% | <0.01% | 46 | 3.25 KB |
| Service enumeration | 1 | 7 | <0.01% | <0.01% | 4,154 | 830.97 KB |
| Local file inclusion | 1 | 4 | <0.01% | <0.01% | 191 | 108.23 KB |

### 3.3 By target platform

| Platform | Attack classes | Target hosts | Flows | % of attacks | % excl. full port scan |
| :--- | ---: | ---: | ---: | ---: | ---: |
| All targets | 1 | 20 | 1,728,220 | 96.08% | – |
| Metasploitable 2 | 16 | 6 | 53,537 | 2.98% | 75.89% |
| Metasploitable 3 | 14 | 5 | 16,360 | 0.91% | 23.19% |
| VulHub | 22 | 7 | 648 | 0.04% | 0.92% |

`All targets` is the full-range port scan (`nmap-full-portscan`), which covers every port; it hit 20 of the 20 logged targets.

### 3.4 All classes

| # | Label | Technique | Platform | Flows | % of all | % of attacks | in 07 | in 10 |
| ---: | :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| 1 | `nmap-full-portscan` | Port scan (full TCP range) | All targets | 1,728,220 | 76.35% | 96.08% | 1,351,575 | 376,645 |
| 2 | `BENIGN` | Benign | – | 464,656 | 20.53% | – | 382,789 | 81,867 |
| 3 | `ms2-mutillidae-sqlmap` | SQL injection | Metasploitable 2 | 53,343 | 2.36% | 2.97% | 45,832 | 7,511 |
| 4 | `ms3-iis-ftp-wordlist` | Brute force (wordlist) | Metasploitable 3 | 15,924 | 0.70% | 0.89% | 15,402 | 522 |
| 5 | `vulnhub-1panel-cve-2024-39907` | Known-vulnerability exploit (CVE/CNVD) | VulHub | 218 | <0.01% | 0.01% | 89 | 129 |
| 6 | `ms3-glassfish-revshell` | Remote code execution (reverse shell) | Metasploitable 3 | 152 | <0.01% | <0.01% | 140 | 12 |
| 7 | `ms3-jenkins-revshell` | Remote code execution (reverse shell) | Metasploitable 3 | 152 | <0.01% | <0.01% | 52 | 100 |
| 8 | `vulnhub-aj-report-cnvd-2024-15077` | Known-vulnerability exploit (CVE/CNVD) | VulHub | 142 | <0.01% | <0.01% | 94 | 48 |
| 9 | `vulnhub-activemq-cve-2022-41678` | Known-vulnerability exploit (CVE/CNVD) | VulHub | 85 | <0.01% | <0.01% | 27 | 58 |
| 10 | `ms3-iis-http-dos` | Denial of service | Metasploitable 3 | 53 | <0.01% | <0.01% | 53 | 0 |
| 11 | `ms2-dvwa-xss-reflected` | Cross-site scripting | Metasploitable 2 | 51 | <0.01% | <0.01% | 46 | 5 |
| 12 | `vulnhub-airflow-cve-2020-17526` | Known-vulnerability exploit (CVE/CNVD) | VulHub | 42 | <0.01% | <0.01% | 42 | 0 |
| 13 | `vulnhub-airflow-cve-2020-11978` | Known-vulnerability exploit (CVE/CNVD) | VulHub | 39 | <0.01% | <0.01% | 39 | 0 |
| 14 | `vulnhub-apache-druid-cve-2021-25646` | Known-vulnerability exploit (CVE/CNVD) | VulHub | 34 | <0.01% | <0.01% | 4 | 30 |
| 15 | `ms3-elasticsearch-revshell` | Remote code execution (reverse shell) | Metasploitable 3 | 28 | <0.01% | <0.01% | 20 | 8 |
| 16 | `vulnhub-activemq-cve-2026-34197` | Known-vulnerability exploit (CVE/CNVD) | VulHub | 21 | <0.01% | <0.01% | 21 | 0 |
| 17 | `ms2-dvwa-sqli-manual` | SQL injection | Metasploitable 2 | 20 | <0.01% | <0.01% | 20 | 0 |
| 18 | `ms2-dvwa-xss-stored` | Cross-site scripting | Metasploitable 2 | 19 | <0.01% | <0.01% | 19 | 0 |
| 19 | `ms2-unrealircd-revshell` | Remote code execution (reverse shell) | Metasploitable 2 | 18 | <0.01% | <0.01% | 15 | 3 |
| 20 | `ms2-dvwa-cmdinject` | OS command injection | Metasploitable 2 | 13 | <0.01% | <0.01% | 13 | 0 |
| 21 | `vulnhub-flask-ssti` | Server-side template injection | VulHub | 12 | <0.01% | <0.01% | 12 | 0 |
| 22 | `ms3-jmx-revshell` | Remote code execution (reverse shell) | Metasploitable 3 | 10 | <0.01% | <0.01% | 10 | 0 |
| 23 | `ms2-dvwa-cmdinject-portscan` | Service scan (single port, pre-exploit) | Metasploitable 2 | 9 | <0.01% | <0.01% | 9 | 0 |
| 24 | `ms2-dvwa-xss-reflected-portscan` | Service scan (single port, pre-exploit) | Metasploitable 2 | 9 | <0.01% | <0.01% | 6 | 3 |
| 25 | `ms2-mutillidae-sqlmap-portscan` | Service scan (single port, pre-exploit) | Metasploitable 2 | 9 | <0.01% | <0.01% | 7 | 2 |
| 26 | `vulnhub-airflow-cve-2020-11981` | Known-vulnerability exploit (CVE/CNVD) | VulHub | 9 | <0.01% | <0.01% | 9 | 0 |
| 27 | `vulnhub-apisix-cve-2020-13945` | Known-vulnerability exploit (CVE/CNVD) | VulHub | 9 | <0.01% | <0.01% | 3 | 6 |
| 28 | `ms2-rservices-portscan` | Service scan (single port, pre-exploit) | Metasploitable 2 | 8 | <0.01% | <0.01% | 7 | 1 |
| 29 | `vulnhub-activemq-cve-2022-41678-portscan` | Service scan (single port, pre-exploit) | VulHub | 8 | <0.01% | <0.01% | 7 | 1 |
| 30 | `ms2-dvwa-lfi-portscan` | Service scan (single port, pre-exploit) | Metasploitable 2 | 7 | <0.01% | <0.01% | 7 | 0 |
| 31 | `ms2-dvwa-sqli-manual-portscan` | Service scan (single port, pre-exploit) | Metasploitable 2 | 7 | <0.01% | <0.01% | 7 | 0 |
| 32 | `ms2-dvwa-xss-stored-portscan` | Service scan (single port, pre-exploit) | Metasploitable 2 | 7 | <0.01% | <0.01% | 7 | 0 |
| 33 | `ms2-rservices-revshell` | Remote code execution (reverse shell) | Metasploitable 2 | 7 | <0.01% | <0.01% | 6 | 1 |
| 34 | `ms3-snmp-enum` | Service enumeration | Metasploitable 3 | 7 | <0.01% | <0.01% | 4 | 3 |
| 35 | `vulnhub-flask-ssti-portscan` | Service scan (single port, pre-exploit) | VulHub | 7 | <0.01% | <0.01% | 7 | 0 |
| 36 | `ms2-unrealircd-portscan` | Service scan (single port, pre-exploit) | Metasploitable 2 | 6 | <0.01% | <0.01% | 6 | 0 |
| 37 | `vulnhub-aj-report-cnvd-2024-15077-portscan` | Service scan (single port, pre-exploit) | VulHub | 6 | <0.01% | <0.01% | 5 | 1 |
| 38 | `ms3-elasticsearch-portscan` | Service scan (single port, pre-exploit) | Metasploitable 3 | 5 | <0.01% | <0.01% | 4 | 1 |
| 39 | `ms3-glassfish-portscan` | Service scan (single port, pre-exploit) | Metasploitable 3 | 5 | <0.01% | <0.01% | 4 | 1 |
| 40 | `ms3-iis-ftp-wordlist-portscan` | Service scan (single port, pre-exploit) | Metasploitable 3 | 5 | <0.01% | <0.01% | 4 | 1 |
| 41 | `ms3-jenkins-portscan` | Service scan (single port, pre-exploit) | Metasploitable 3 | 5 | <0.01% | <0.01% | 4 | 1 |
| 42 | `ms3-jmx-portscan` | Service scan (single port, pre-exploit) | Metasploitable 3 | 5 | <0.01% | <0.01% | 4 | 1 |
| 43 | `ms3-snmp-portscan` | Service scan (single port, pre-exploit) | Metasploitable 3 | 5 | <0.01% | <0.01% | 3 | 2 |
| 44 | `ms2-dvwa-lfi` | Local file inclusion | Metasploitable 2 | 4 | <0.01% | <0.01% | 4 | 0 |
| 45 | `ms3-iis-http-dos-portscan` | Service scan (single port, pre-exploit) | Metasploitable 3 | 4 | <0.01% | <0.01% | 4 | 0 |
| 46 | `vulnhub-airflow-cve-2020-17526-portscan` | Service scan (single port, pre-exploit) | VulHub | 3 | <0.01% | <0.01% | 3 | 0 |
| 47 | `vulnhub-apache-druid-cve-2021-25646-portscan` | Service scan (single port, pre-exploit) | VulHub | 3 | <0.01% | <0.01% | 2 | 1 |
| 48 | `vulnhub-1panel-cve-2024-39907-portscan` | Service scan (single port, pre-exploit) | VulHub | 2 | <0.01% | <0.01% | 1 | 1 |
| 49 | `vulnhub-apache-cxf-cve-2024-28752` | Known-vulnerability exploit (CVE/CNVD) | VulHub | 2 | <0.01% | <0.01% | 2 | 0 |
| 50 | `vulnhub-apisix-cve-2020-13945-portscan` | Service scan (single port, pre-exploit) | VulHub | 2 | <0.01% | <0.01% | 1 | 1 |
| 51 | `vulnhub-activemq-cve-2026-34197-portscan` | Service scan (single port, pre-exploit) | VulHub | 1 | <0.01% | <0.01% | 1 | 0 |
| 52 | `vulnhub-airflow-cve-2020-11978-portscan` | Service scan (single port, pre-exploit) | VulHub | 1 | <0.01% | <0.01% | 1 | 0 |
| 53 | `vulnhub-airflow-cve-2020-11981-portscan` | Service scan (single port, pre-exploit) | VulHub | 1 | <0.01% | <0.01% | 1 | 0 |
| 54 | `vulnhub-apache-cxf-cve-2024-28752-portscan` | Service scan (single port, pre-exploit) | VulHub | 1 | <0.01% | <0.01% | 1 | 0 |

### 3.5 Class balance

| Flows per attack class | Classes | Flows | % of attacks |
| :--- | ---: | ---: | ---: |
| ≥ 100,000 | 1 | 1,728,220 | 96.08% |
| 10,000 – 99,999 | 2 | 69,267 | 3.85% |
| 1,000 – 9,999 | 0 | 0 | 0% |
| 100 – 999 | 4 | 664 | 0.04% |
| 10 – 99 | 14 | 445 | 0.02% |
| 1 – 9 | 32 | 169 | <0.01% |

| Balance metric | Value |
| :--- | :--- |
| Largest / smallest attack class | 1,728,220 / 1 = 1,728,220× |
| Median attack class size | 8 |
| `nmap-full-portscan` share of attack flows | 96.08% |
| Effective number of attack classes (exp of Shannon entropy) | 1.21 of 53 |
| Effective number of classes incl. benign | 1.94 of 54 |
| Attack flows excluding `nmap-full-portscan` | 70,545 in 52 classes |
| …largest of those | `ms2-mutillidae-sqlmap` 75.62%, `ms3-iis-ftp-wordlist` 22.57%, `vulnhub-1panel-cve-2024-39907` 0.31%, `ms3-glassfish-revshell` 0.22% |

The largest class, `nmap-full-portscan`, holds 96.08% of attack flows, while the median attack class has 8 flows. Training on this dataset needs class weighting, re-sampling, or a per-class evaluation (macro-averaged metrics) so that a classifier is not judged by its majority classes alone.

## 4. Traffic profile per class

Per-flow medians show what a typical flow of each class looks like. *No reply* is the share of flows where the responder sent nothing back. *SYN-ACK* is the share of TCP flows where the responder accepted the connection.

| Label | Flows | Median packets | Median bytes | Mean bytes | Median duration (s) | p95 duration (s) | No reply | SYN-ACK (TCP) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `nmap-full-portscan` | 1,728,220 | 2 | 128 | 128 | 0.000 | 0.001 | 0.3% | 0.0% |
| `BENIGN` | 464,656 | 10 | 1,376 | 1,017 | 0.004 | 35.854 | 12.8% | 87.4% |
| `ms2-mutillidae-sqlmap` | 53,343 | 41 | 28,247 | 29,279 | 0.822 | 1.874 | 0.0% | 100.0% |
| `ms3-iis-ftp-wordlist` | 15,924 | 13 | 1,035 | 1,014 | 0.247 | 0.871 | 0.0% | 100.0% |
| `vulnhub-1panel-cve-2024-39907` | 218 | 12 | 2,350 | 22,291 | 0.174 | 1.343 | 0.0% | 100.0% |
| `ms3-glassfish-revshell` | 152 | 34 | 15,530 | 123,849 | 30.826 | 151.929 | 0.0% | 97.4% |
| `ms3-jenkins-revshell` | 152 | 35 | 21,224 | 23,777 | 0.463 | 6.492 | 0.0% | 100.0% |
| `vulnhub-aj-report-cnvd-2024-15077` | 142 | 9 | 1,018 | 65,746 | 0.103 | 58.159 | 1.4% | 97.9% |
| `vulnhub-activemq-cve-2022-41678` | 85 | 11 | 1,862 | 8,974 | 0.129 | 163.524 | 0.0% | 100.0% |
| `ms3-iis-http-dos` | 53 | 10 | 1,546 | 211,309 | 5.128 | 134.489 | 3.8% | 67.9% |
| `ms2-dvwa-xss-reflected` | 51 | 17 | 6,559 | 14,687 | 17.117 | 53.541 | 0.0% | 100.0% |
| `vulnhub-airflow-cve-2020-17526` | 42 | 20 | 9,544 | 28,708 | 0.446 | 1.937 | 0.0% | 76.2% |
| `vulnhub-airflow-cve-2020-11978` | 39 | 27 | 14,181 | 40,848 | 0.611 | 4.880 | 0.0% | 100.0% |
| `vulnhub-apache-druid-cve-2021-25646` | 34 | 10 | 2,158 | 23,726 | 0.264 | 1.601 | 0.0% | 100.0% |
| `ms3-elasticsearch-revshell` | 28 | 12 | 2,208 | 26,444 | 0.468 | 3.416 | 0.0% | 100.0% |
| `vulnhub-activemq-cve-2026-34197` | 21 | 14 | 2,381 | 5,906 | 0.581 | 31.519 | 0.0% | 95.2% |
| `ms2-dvwa-sqli-manual` | 20 | 28 | 12,608 | 17,544 | 39.469 | 113.230 | 0.0% | 100.0% |
| `ms2-dvwa-xss-stored` | 19 | 20 | 7,425 | 15,582 | 17.638 | 116.573 | 0.0% | 100.0% |
| `ms2-unrealircd-revshell` | 18 | 13 | 1,346 | 1,471 | 47.157 | 48.705 | 0.0% | 100.0% |
| `ms2-dvwa-cmdinject` | 13 | 44 | 24,624 | 23,564 | 29.716 | 63.512 | 0.0% | 100.0% |
| `vulnhub-flask-ssti` | 12 | 2 | 142 | 271 | 0.001 | 6.012 | 0.0% | 0.0% |
| `ms3-jmx-revshell` | 10 | 24 | 6,486 | 6,540 | 14.751 | 27.436 | 0.0% | 100.0% |
| `ms2-dvwa-cmdinject-portscan` | 9 | 3 | 192 | 1,856 | 0.225 | 63.188 | 0.0% | 100.0% |
| `ms2-dvwa-xss-reflected-portscan` | 9 | 3 | 192 | 2,835 | 0.048 | 13.497 | 0.0% | 100.0% |
| `ms2-mutillidae-sqlmap-portscan` | 9 | 3 | 192 | 2,314 | 0.047 | 255.927 | 0.0% | 100.0% |
| `vulnhub-airflow-cve-2020-11981` | 9 | 14 | 2,220 | 2,220 | 0.308 | 0.386 | 0.0% | 100.0% |
| `vulnhub-apisix-cve-2020-13945` | 9 | 13 | 2,255 | 2,372 | 60.066 | 151.759 | 0.0% | 100.0% |
| `ms2-rservices-portscan` | 8 | 3 | 192 | 6,091 | 0.035 | 63.764 | 0.0% | 100.0% |
| `vulnhub-activemq-cve-2022-41678-portscan` | 8 | 3 | 192 | 176 | 0.035 | 0.106 | 0.0% | 75.0% |
| `ms2-dvwa-lfi-portscan` | 7 | 3 | 192 | 2,142 | 0.034 | 53.695 | 0.0% | 100.0% |
| `ms2-dvwa-sqli-manual-portscan` | 7 | 3 | 192 | 550 | 0.032 | 61.072 | 0.0% | 100.0% |
| `ms2-dvwa-xss-stored-portscan` | 7 | 3 | 192 | 1,354 | 0.035 | 110.074 | 0.0% | 100.0% |
| `ms2-rservices-revshell` | 7 | 34 | 3,151 | 9,101 | 6.740 | 40.485 | 0.0% | 100.0% |
| `ms3-snmp-enum` | 7 | 966 | 189,653 | 118,710 | 16.796 | 33.466 | 42.9% | – |
| `vulnhub-flask-ssti-portscan` | 7 | 2 | 142 | 136 | 0.001 | 0.001 | 0.0% | 0.0% |
| `ms2-unrealircd-portscan` | 6 | 3 | 192 | 192 | 0.034 | 0.151 | 0.0% | 100.0% |
| `vulnhub-aj-report-cnvd-2024-15077-portscan` | 6 | 3 | 192 | 192 | 0.058 | 0.083 | 0.0% | 100.0% |
| `ms3-elasticsearch-portscan` | 5 | 3 | 192 | 192 | 0.089 | 0.140 | 0.0% | 100.0% |
| `ms3-glassfish-portscan` | 5 | 3 | 192 | 192 | 0.050 | 0.090 | 0.0% | 100.0% |
| `ms3-iis-ftp-wordlist-portscan` | 5 | 3 | 192 | 192 | 0.073 | 0.140 | 0.0% | 100.0% |
| `ms3-jenkins-portscan` | 5 | 3 | 192 | 192 | 0.049 | 0.135 | 0.0% | 100.0% |
| `ms3-jmx-portscan` | 5 | 3 | 192 | 192 | 0.091 | 0.126 | 0.0% | 100.0% |
| `ms3-snmp-portscan` | 5 | 3 | 300 | 261 | 0.000 | 0.022 | 40.0% | – |
| `ms2-dvwa-lfi` | 4 | 52 | 29,197 | 27,058 | 32.668 | 48.529 | 0.0% | 100.0% |
| `ms3-iis-http-dos-portscan` | 4 | 3 | 192 | 192 | 0.037 | 0.125 | 0.0% | 100.0% |
| `vulnhub-airflow-cve-2020-17526-portscan` | 3 | 3 | 192 | 171 | 0.030 | 0.072 | 0.0% | 66.7% |
| `vulnhub-apache-druid-cve-2021-25646-portscan` | 3 | 3 | 192 | 192 | 0.085 | 0.091 | 0.0% | 100.0% |
| `vulnhub-1panel-cve-2024-39907-portscan` | 2 | 3 | 192 | 192 | 0.032 | 0.035 | 0.0% | 100.0% |
| `vulnhub-apache-cxf-cve-2024-28752` | 2 | 10 | 1,827 | 1,827 | 0.525 | 0.587 | 0.0% | 100.0% |
| `vulnhub-apisix-cve-2020-13945-portscan` | 2 | 3 | 192 | 192 | 0.054 | 0.061 | 0.0% | 100.0% |
| `vulnhub-activemq-cve-2026-34197-portscan` | 1 | 3 | 192 | 192 | 0.029 | 0.029 | 0.0% | 100.0% |
| `vulnhub-airflow-cve-2020-11978-portscan` | 1 | 3 | 192 | 192 | 0.118 | 0.118 | 0.0% | 100.0% |
| `vulnhub-airflow-cve-2020-11981-portscan` | 1 | 2 | 128 | 128 | 0.001 | 0.001 | 0.0% | 0.0% |
| `vulnhub-apache-cxf-cve-2024-28752-portscan` | 1 | 3 | 192 | 192 | 0.038 | 0.038 | 0.0% | 100.0% |

## 5. Attack records, attackers and targets

Attackers bracket every attack with `attacklog start` / `attacklog end`. Each record holds the attacker, target IP, target port(s), protocol, attack name, UTC start/end time and an outcome (`success`, `ran` = executed without exploiting, `error`).

### 5.1 How the labels were assigned

| Step | Capture 07 | Capture 10 | Total |
| :--- | ---: | ---: | ---: |
| Logged attack records | 229 | 38 | 267 |
| …status `success` | 38 | 6 | 44 |
| …status `ran` | 172 | 30 | 202 |
| …status `error` | 19 | 2 | 21 |
| Records that matched no flow | 36 | 1 | 37 |
| Flows labeled by time window (±1 s) | 1,215,483 | 319,010 | 1,534,493 |
| Flows labeled by tuple fallback | 198,183 | 66,093 | 264,276 |
| Manual overrides → another attack | 11 | 1 | 12 |
| Manual overrides → BENIGN | 0 | 4 | 4 |
| Final attack flows | 1,413,666 | 385,099 | 1,798,765 |
| Final benign flows | 382,789 | 81,867 | 464,656 |

A flow from an attacker IP is labeled when its src IP, dst IP, dst port and protocol match a record and its time overlaps the record's window. If the addresses and port match but no window does, the flow goes to the nearest window with the same addresses and port (tuple fallback). Everything else is BENIGN. The manual overrides (`relabel_overrides.csv`) correct reviewed fallback mistakes and are applied only in this unified dataset.

### 5.2 Attackers

| Attacker | Source IP | Capture | Records | success | ran | error | Targets | Attack names | Attack flows | % of attacks | Active days | First start → last end |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| attacker_1 | 192.168.71.203 | 07 | 57 | 10 | 40 | 7 | 4 | 45 | 343,518 | 19.10% | 2 | 2026-07-14 19:14 → 2026-07-16 18:15 |
| attacker_2 | 192.168.71.204 | 07 | 63 | 8 | 52 | 3 | 4 | 43 | 349,476 | 19.43% | 2 | 2026-07-15 18:34 → 2026-07-16 14:49 |
| attacker_3 | 192.168.71.201 | 07 | 44 | 8 | 34 | 2 | 3 | 31 | 216,442 | 12.03% | 3 | 2026-07-14 18:03 → 2026-07-16 11:04 |
| attacker_5 | 192.168.71.206 | 07 | 65 | 12 | 46 | 7 | 4 | 39 | 504,230 | 28.03% | 4 | 2026-07-14 14:20 → 2026-07-17 09:17 |
| attacker_4 | 192.168.71.205 | 10 | 3 | 0 | 3 | 0 | 1 | 3 | 74,062 | 4.12% | 1 | 2026-10-05 05:45 → 2026-10-05 06:11 |
| attacker_7 | 192.168.71.12 | 10 | 35 | 6 | 27 | 2 | 4 | 30 | 311,037 | 17.29% | 3 | 2026-10-01 14:42 → 2026-10-03 20:38 |

### 5.3 Targets

| Target IP | Platform (from attack names) | Capture | Attacked by | Records | Attack flows | Attack classes |
| :--- | :--- | :--- | :--- | :--- | ---: | ---: |
| 192.168.77.220 | VulHub | 07 | attacker_5 | 6 | 87,371 | 1 |
| 192.168.77.221 | VulHub | 10 | attacker_7 | 8 | 65,830 | 7 |
| 192.168.77.222 | Metasploitable 2 | 07 | attacker_2 | 33 | 142,559 | 17 |
| 192.168.77.223 | Metasploitable 2 | 07 | attacker_3 | 28 | 80,067 | 17 |
| 192.168.77.224 | Metasploitable 2 | 10 | attacker_4 | 3 | 74,062 | 3 |
| 192.168.77.225 | Metasploitable 2 | 07 | attacker_5 | 28 | 85,828 | 17 |
| 192.168.77.227 | Metasploitable 2 | 10 | attacker_7 | 8 | 69,387 | 8 |
| 192.168.77.230 | VulHub | 10 | attacker_7 | 6 | 131,846 | 5 |
| 192.168.77.235 | VulHub | 07 | attacker_1 | 11 | 135,552 | 8 |
| 192.168.77.236 | VulHub | 07 | attacker_1 | 9 | 67,475 | 7 |
| 192.168.77.237 | VulHub | 07 | attacker_2 | 7 | 66,042 | 7 |
| 192.168.77.238 | VulHub | 07 | attacker_2 | 7 | 65,914 | 7 |
| 192.168.77.239 | unknown (scan only) | 07 | attacker_3 | 1 | 65,757 | 1 |
| 192.168.77.240 | Metasploitable 3 | 07 | attacker_2 | 16 | 74,961 | 15 |
| 192.168.77.242 | Metasploitable 3 | 07 | attacker_3 | 15 | 70,618 | 14 |
| 192.168.77.244 | Metasploitable 3 | 07 | attacker_1 | 15 | 71,324 | 15 |
| 192.168.77.246 | Metasploitable 3 | 07 | attacker_5 | 18 | 66,217 | 14 |
| 192.168.77.248 | Metasploitable 3 | 10 | attacker_7 | 13 | 43,974 | 12 |
| 192.168.77.249 | Metasploitable 2 | 07 | attacker_1 | 22 | 69,167 | 16 |
| 192.168.77.252 | VulHub | 07 | attacker_5 | 13 | 264,814 | 7 |

### 5.4 Logged records per class

<details>
<summary>53 attack names, 267 records</summary>

| Attack name | Records | success | ran | error | Records with no flow | Attackers | Targets | Flows in dataset |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `nmap-full-portscan` | 32 | 1 | 29 | 2 | 9 | 6 | 20 | 1,728,220 |
| `ms2-mutillidae-sqlmap` | 8 | 0 | 8 | 0 | 0 | 6 | 6 | 53,343 |
| `ms3-iis-ftp-wordlist` | 5 | 2 | 3 | 0 | 0 | 5 | 5 | 15,924 |
| `vulnhub-1panel-cve-2024-39907` | 2 | 2 | 0 | 0 | 0 | 2 | 2 | 218 |
| `ms3-glassfish-revshell` | 5 | 1 | 4 | 0 | 0 | 5 | 5 | 152 |
| `ms3-jenkins-revshell` | 5 | 0 | 5 | 0 | 1 | 5 | 5 | 152 |
| `vulnhub-aj-report-cnvd-2024-15077` | 6 | 1 | 3 | 2 | 0 | 3 | 3 | 142 |
| `vulnhub-activemq-cve-2022-41678` | 3 | 2 | 1 | 0 | 0 | 3 | 3 | 85 |
| `ms3-iis-http-dos` | 4 | 4 | 0 | 0 | 0 | 4 | 4 | 53 |
| `ms2-dvwa-xss-reflected` | 8 | 2 | 5 | 1 | 1 | 5 | 5 | 51 |
| `vulnhub-airflow-cve-2020-17526` | 3 | 1 | 1 | 1 | 0 | 2 | 2 | 42 |
| `vulnhub-airflow-cve-2020-11978` | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 39 |
| `vulnhub-apache-druid-cve-2021-25646` | 4 | 3 | 1 | 0 | 0 | 3 | 3 | 34 |
| `ms3-elasticsearch-revshell` | 5 | 0 | 5 | 0 | 0 | 5 | 5 | 28 |
| `vulnhub-activemq-cve-2026-34197` | 1 | 0 | 0 | 1 | 0 | 1 | 1 | 21 |
| `ms2-dvwa-sqli-manual` | 5 | 3 | 2 | 0 | 0 | 4 | 4 | 20 |
| `ms2-dvwa-xss-stored` | 5 | 2 | 3 | 0 | 0 | 4 | 4 | 19 |
| `ms2-unrealircd-revshell` | 8 | 0 | 7 | 1 | 2 | 5 | 5 | 18 |
| `ms2-dvwa-cmdinject` | 5 | 2 | 2 | 1 | 0 | 4 | 4 | 13 |
| `vulnhub-flask-ssti` | 2 | 0 | 0 | 2 | 1 | 2 | 2 | 12 |
| `ms3-jmx-revshell` | 5 | 0 | 2 | 3 | 1 | 5 | 5 | 10 |
| `ms2-dvwa-cmdinject-portscan` | 5 | 0 | 5 | 0 | 0 | 4 | 4 | 9 |
| `ms2-dvwa-xss-reflected-portscan` | 9 | 0 | 8 | 1 | 3 | 5 | 5 | 9 |
| `ms2-mutillidae-sqlmap-portscan` | 7 | 0 | 7 | 0 | 0 | 6 | 6 | 9 |
| `vulnhub-airflow-cve-2020-11981` | 2 | 0 | 0 | 2 | 1 | 2 | 2 | 9 |
| `vulnhub-apisix-cve-2020-13945` | 2 | 2 | 0 | 0 | 0 | 2 | 2 | 9 |
| `ms2-rservices-portscan` | 10 | 2 | 8 | 0 | 3 | 5 | 5 | 8 |
| `vulnhub-activemq-cve-2022-41678-portscan` | 4 | 0 | 4 | 0 | 0 | 3 | 3 | 8 |
| `ms2-dvwa-lfi-portscan` | 5 | 0 | 5 | 0 | 0 | 4 | 4 | 7 |
| `ms2-dvwa-sqli-manual-portscan` | 5 | 0 | 5 | 0 | 0 | 4 | 4 | 7 |
| `ms2-dvwa-xss-stored-portscan` | 5 | 0 | 5 | 0 | 0 | 4 | 4 | 7 |
| `ms2-rservices-revshell` | 10 | 6 | 2 | 2 | 4 | 5 | 5 | 7 |
| `ms3-snmp-enum` | 5 | 4 | 1 | 0 | 0 | 5 | 5 | 7 |
| `vulnhub-flask-ssti-portscan` | 3 | 0 | 3 | 0 | 0 | 2 | 2 | 7 |
| `ms2-unrealircd-portscan` | 11 | 0 | 11 | 0 | 6 | 4 | 4 | 6 |
| `vulnhub-aj-report-cnvd-2024-15077-portscan` | 5 | 0 | 5 | 0 | 0 | 3 | 3 | 6 |
| `ms3-elasticsearch-portscan` | 5 | 0 | 5 | 0 | 0 | 5 | 5 | 5 |
| `ms3-glassfish-portscan` | 7 | 0 | 6 | 1 | 2 | 5 | 5 | 5 |
| `ms3-iis-ftp-wordlist-portscan` | 5 | 0 | 5 | 0 | 0 | 5 | 5 | 5 |
| `ms3-jenkins-portscan` | 5 | 0 | 5 | 0 | 0 | 5 | 5 | 5 |
| `ms3-jmx-portscan` | 5 | 0 | 5 | 0 | 0 | 5 | 5 | 5 |
| `ms3-snmp-portscan` | 5 | 0 | 5 | 0 | 1 | 5 | 5 | 5 |
| `ms2-dvwa-lfi` | 5 | 2 | 2 | 1 | 1 | 4 | 4 | 4 |
| `ms3-iis-http-dos-portscan` | 4 | 0 | 4 | 0 | 0 | 4 | 4 | 4 |
| `vulnhub-airflow-cve-2020-17526-portscan` | 3 | 0 | 3 | 0 | 0 | 2 | 2 | 3 |
| `vulnhub-apache-druid-cve-2021-25646-portscan` | 3 | 0 | 3 | 0 | 0 | 3 | 3 | 3 |
| `vulnhub-1panel-cve-2024-39907-portscan` | 2 | 0 | 2 | 0 | 0 | 2 | 2 | 2 |
| `vulnhub-apache-cxf-cve-2024-28752` | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 2 |
| `vulnhub-apisix-cve-2020-13945-portscan` | 2 | 0 | 2 | 0 | 0 | 2 | 2 | 2 |
| `vulnhub-activemq-cve-2026-34197-portscan` | 1 | 0 | 1 | 0 | 0 | 1 | 1 | 1 |
| `vulnhub-airflow-cve-2020-11978-portscan` | 1 | 0 | 1 | 0 | 0 | 1 | 1 | 1 |
| `vulnhub-airflow-cve-2020-11981-portscan` | 2 | 0 | 2 | 0 | 1 | 2 | 2 | 1 |
| `vulnhub-apache-cxf-cve-2024-28752-portscan` | 1 | 0 | 1 | 0 | 0 | 1 | 1 | 1 |

</details>

### 5.5 Records that matched no flow

These records produced no matching traffic. Typical causes are dry runs or sessions repeated later, attacks that failed before sending anything, records logged against the wrong target, and records logged while the attacker's clock was out of sync. The attackers' notes often tell which.

<details>
<summary>37 records</summary>

| Capture | Attacker | Attack name | Target | Port(s) | Start | Status | Attacker's note |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 07 | attacker_5 | `nmap-full-portscan` | 192.168.77.225 | 1-65535 | 2026-07-14 14:20 | error | pc went boom.. |
| 07 | attacker_5 | `nmap-full-portscan` | 192.168.77.225 | 1-65535 | 2026-07-14 14:30 | ran | all ports in ignored state |
| 07 | attacker_5 | `nmap-full-portscan` | 192.168.77.225 | 1-65535 | 2026-07-14 17:06 | ran | all ports in ignored state |
| 07 | attacker_5 | `ms2-rservices-portscan` | 192.168.77.225 | 513 | 2026-07-14 17:14 | ran |  |
| 07 | attacker_5 | `ms2-rservices-revshell` | 192.168.77.225 | 513 | 2026-07-14 17:15 | error | could not make a connection, port is up and active though |
| 07 | attacker_5 | `ms2-unrealircd-portscan` | 192.168.77.225 | 6667 | 2026-07-14 17:17 | ran |  |
| 07 | attacker_5 | `ms2-unrealircd-portscan` | 192.168.77.225 | 6667 | 2026-07-14 17:18 | ran | exploit completed, but no session was created |
| 07 | attacker_3 | `nmap-full-portscan` | 192.168.77.223 | 1-65535 | 2026-07-14 18:03 | ran |  |
| 07 | attacker_5 | `ms2-dvwa-xss-reflected-portscan` | 192.168.77.225 | 80 | 2026-07-14 18:07 | ran |  |
| 07 | attacker_5 | `ms2-dvwa-xss-reflected-portscan` | 192.168.77.225 | 80 | 2026-07-14 18:07 | error | machine seems offline |
| 07 | attacker_3 | `ms2-rservices-portscan` | 192.168.77.223 | 513 | 2026-07-14 18:12 | ran |  |
| 07 | attacker_3 | `ms2-rservices-revshell` | 192.168.77.223 | 513 | 2026-07-14 18:14 | ran |  |
| 07 | attacker_3 | `ms2-rservices-revshell` | 192.168.77.223 | 513 | 2026-07-14 18:19 | ran | rlogin nemoze da se povrze na  TCP port 513, ne dobiv nikakov shell |
| 07 | attacker_3 | `ms2-unrealircd-portscan` | 192.168.77.223 | 6667 | 2026-07-14 18:24 | ran |  |
| 07 | attacker_3 | `ms2-unrealircd-revshell` | 192.168.77.223 | 6667 | 2026-07-14 18:24 | ran | Exploitot bese uspesen, no ne dobiv konekcija |
| 07 | attacker_3 | `ms2-unrealircd-portscan` | 192.168.77.223 | 3455 | 2026-07-14 18:30 | ran |  |
| 07 | attacker_3 | `ms2-dvwa-xss-reflected-portscan` | 192.168.77.223 | 80 | 2026-07-14 18:31 | ran |  |
| 07 | attacker_3 | `ms2-dvwa-xss-reflected` | 192.168.77.223 | 80 | 2026-07-14 18:32 | error | DVWA HTTP service unreachable; connection timed out before payload submission |
| 07 | attacker_1 | `nmap-full-portscan` | 192.168.77.249 | 1-65535 | 2026-07-14 19:14 | ran |  |
| 07 | attacker_1 | `ms2-rservices-portscan` | 192.168.77.249 | 513 | 2026-07-14 19:19 | ran |  |
| 07 | attacker_1 | `ms2-rservices-revshell` | 192.168.77.249 | 513 | 2026-07-14 19:20 | error |  |
| 07 | attacker_1 | `ms2-unrealircd-portscan` | 192.168.77.249 | 6667 | 2026-07-14 19:23 | ran |  |
| 07 | attacker_1 | `ms2-unrealircd-revshell` | 192.168.77.249 | 6667 | 2026-07-14 19:23 | error |  |
| 07 | attacker_5 | `nmap-full-portscan` | 192.168.77.246 | 1-65535 | 2026-07-14 19:58 | ran |  |
| 07 | attacker_5 | `ms3-glassfish-portscan` | 192.168.77.246 | 4848 | 2026-07-15 05:19 | ran |  |
| 07 | attacker_5 | `ms3-glassfish-portscan` | 192.168.77.246 | 4848 | 2026-07-15 05:20 | error | aborted it because i noticed my sys clock unsynced |
| 07 | attacker_5 | `ms2-unrealircd-portscan` | 192.168.77.225 | 6667 | 2026-07-15 12:40 | ran |  |
| 07 | attacker_5 | `ms3-jenkins-revshell` | 192.168.77.246 | 8484 | 2026-07-15 19:23 | ran | failed due to unexpected reply from server |
| 07 | attacker_2 | `nmap-full-portscan` | 192.168.77.240 | 1-65535 | 2026-07-15 21:22 | ran |  |
| 07 | attacker_1 | `ms2-dvwa-lfi` | 192.168.77.249 | 80 | 2026-07-16 00:28 | error |  |
| 07 | attacker_3 | `ms3-snmp-portscan` | 192.168.77.242 | 161 | 2026-07-16 10:03 | ran |  |
| 07 | attacker_1 | `vulnhub-flask-ssti` | 192.168.77.235 | 8000 | 2026-07-16 17:56 | error |  |
| 07 | attacker_5 | `nmap-full-portscan` | 192.168.77.220 | 1-65535 | 2026-07-16 18:19 | ran |  |
| 07 | attacker_5 | `nmap-full-portscan` | 192.168.77.220 | 1-65535 | 2026-07-17 08:48 | ran |  |
| 07 | attacker_5 | `vulnhub-airflow-cve-2020-11981-portscan` | 192.168.77.220 | 6379 | 2026-07-17 08:49 | ran |  |
| 07 | attacker_5 | `vulnhub-airflow-cve-2020-11981` | 192.168.77.220 | 6379 | 2026-07-17 08:49 | error | dnf |
| 10 | attacker_7 | `ms3-jmx-revshell` | 192.168.77.248 | 1617 | 2026-10-03 20:36 | error |  |

</details>

### 5.6 Known labeling limitations

- **Tuple fallback.** 264,276 attack flows (14.69% of attack flows) match a record's addresses and port but fall outside every logged time window, so their label comes from the nearest window. Typical causes are a scan the attacker repeated without logging it, or an attack record left open too long.
- **Target → attacker traffic is BENIGN.** attacklog records attacker-initiated traffic only, so the 551 flows from targets to attackers are labeled BENIGN although they belong to attacks. Main attacker-side ports: 80 (484), 4444 (53), 8080 (5), 4447 (5). Port 80 is typically a payload download from an attacker-run web server. Port 4444 is Metasploit's default reverse-shell listener.
- **Benign attacker → target flows.** 140 flows: 118 ICMP, 22 TCP. ICMP flows (typically host-discovery pings) never match, because attack records name TCP or UDP. The rest match no attack record or were set to BENIGN by one of the 4 manual overrides.
- **Records without traffic.** 37 of 267 records matched no flow (section 5.5). Before treating such an attack as missing, check whether it was repeated and logged again later.

## 6. Flow characteristics

### 6.1 Distributions

| Metric | Flows | Mean | p25 | Median | p75 | p95 | p99 | Max |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Duration (s) | all | 0.947 | 0.000 | 0.000 | 0.001 | 0.199 | 60.004 | 786.258 |
| Duration (s) | attack | 0.134 | 0.000 | 0.000 | 0.001 | 0.001 | 0.930 | 786.258 |
| Duration (s) | benign | 4.095 | 0.000 | 0.004 | 0.193 | 35.854 | 119.704 | 700.416 |
| Packets | all | 4 | 2 | 2 | 2 | 16 | 42 | 11,951 |
| Packets | attack | 3 | 2 | 2 | 2 | 2 | 44 | 3,308 |
| Packets | benign | 9 | 2 | 10 | 16 | 16 | 24 | 11,951 |
| Bytes | all | 1,028 | 128 | 128 | 128 | 1,504 | 28,378 | 3,568,077 |
| Bytes | attack | 1,031 | 128 | 128 | 128 | 128 | 28,501 | 3,568,077 |
| Bytes | benign | 1,017 | 178 | 1,376 | 1,504 | 1,956 | 2,206 | 1,344,682 |

### 6.2 Direction and TCP behaviour

| Group | Flows | Single-packet | No reply | TCP flows | TCP SYN-ACK | TCP rejected (RST) | TCP with FIN |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **All flows** | 2,263,421 | 1.8% | 2.9% | 1,904,360 | 8.6% | 90.8% | 8.4% |
| **Attack** | 1,798,765 | 0.3% | 0.3% | 1,798,753 | 3.9% | 95.8% | 3.9% |
| **Benign** | 464,656 | 7.8% | 12.8% | 105,607 | 87.4% | 6.7% | 84.6% |
| Port scan (full TCP range) | 1,728,220 | 0.3% | 0.3% | 1,728,220 | 0.0% | 99.7% | <0.01% |
| SQL injection | 53,363 | 0% | 0% | 53,363 | 100.0% | 0% | 100.0% |
| Brute force (wordlist) | 15,924 | 0% | 0% | 15,924 | 100.0% | 0.0% | 100.0% |
| Known-vulnerability exploit (CVE/CNVD) | 601 | 0% | 0.3% | 601 | 97.7% | 1.8% | 78.5% |
| Remote code execution (reverse shell) | 367 | 0% | 0% | 367 | 98.9% | 1.1% | 97.5% |
| Service scan (single port, pre-exploit) | 131 | 0% | 1.5% | 126 | 91.3% | 8.7% | 11.9% |
| Cross-site scripting | 70 | 0% | 0% | 70 | 100.0% | 0% | 98.6% |
| Denial of service | 53 | 0% | 3.8% | 53 | 67.9% | 28.3% | 50.9% |
| OS command injection | 13 | 0% | 0% | 13 | 100.0% | 0% | 100.0% |
| Server-side template injection | 12 | 0% | 0% | 12 | 0% | 100.0% | 0% |
| Service enumeration | 7 | 0% | 42.9% | 0 | – | – | – |
| Local file inclusion | 4 | 0% | 0% | 4 | 100.0% | 0% | 100.0% |

*TCP rejected* = the responder answered only with RST (closed port). For `nmap-full-portscan`, 99.67% of the TCP probes were rejected and 0.03% accepted (open ports).

## 7. Protocols and applications

### 7.1 Transport protocol

| Protocol | Flows | % of all | Attack flows | Benign flows | Attack share | Packets | Bytes |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP (6) | 1,904,360 | 84.14% | 1,798,753 | 105,607 | 94.45% | 7,288,630 | 2.06 GB |
| UDP (17) | 333,115 | 14.72% | 12 | 333,103 | <0.01% | 2,743,301 | 259.38 MB |
| IGMP (2) | 25,814 | 1.14% | 0 | 25,814 | 0% | 46,226 | 3.42 MB |
| ICMP (1) | 132 | <0.01% | 0 | 132 | 0% | 682 | 49.01 KB |

IP version: IPv4 2,258,209 (99.77%), IPv6 5,212 (0.23%).

### 7.2 Applications (nDPI)

Top 15 over all flows:

| Application | Flows | % of group | Attack flows | Benign flows |
| :--- | ---: | ---: | ---: | ---: |
| Unknown | 1,731,996 | 76.52% | 1,724,450 | 7,546 |
| DNS | 154,881 | 6.84% | 29 | 154,852 |
| HTTP | 150,166 | 6.63% | 54,228 | 95,938 |
| NTP | 146,251 | 6.46% | 0 | 146,251 |
| IGMP | 25,814 | 1.14% | 0 | 25,814 |
| FTP_CONTROL | 15,960 | 0.71% | 15,959 | 1 |
| LLMNR | 10,193 | 0.45% | 26 | 10,167 |
| NetBIOS.SMBv1 | 8,546 | 0.38% | 0 | 8,546 |
| NetBIOS | 5,737 | 0.25% | 28 | 5,709 |
| DNS.Microsoft | 4,598 | 0.20% | 0 | 4,598 |
| TLS | 2,738 | 0.12% | 310 | 2,428 |
| DNS.Canonical | 2,494 | 0.11% | 0 | 2,494 |
| BitTorrent | 293 | 0.01% | 292 | 1 |
| POP3 | 146 | <0.01% | 28 | 118 |
| ICMP | 132 | <0.01% | 0 | 132 |

Top 10 among attack flows and among benign flows:

| # | Attack: application | Flows | % of attacks | Benign: application | Flows | % of benign |
| ---: | :--- | ---: | ---: | :--- | ---: | ---: |
| 1 | Unknown | 1,724,450 | 95.87% | DNS | 154,852 | 33.33% |
| 2 | HTTP | 54,228 | 3.01% | NTP | 146,251 | 31.48% |
| 3 | FTP_CONTROL | 15,959 | 0.89% | HTTP | 95,938 | 20.65% |
| 4 | TLS | 310 | 0.02% | IGMP | 25,814 | 5.56% |
| 5 | BitTorrent | 292 | 0.02% | LLMNR | 10,167 | 2.19% |
| 6 | Viber | 111 | <0.01% | NetBIOS.SMBv1 | 8,546 | 1.84% |
| 7 | VNC | 80 | <0.01% | Unknown | 7,546 | 1.62% |
| 8 | Syslog | 79 | <0.01% | NetBIOS | 5,709 | 1.23% |
| 9 | HTTP_Proxy | 71 | <0.01% | DNS.Microsoft | 4,598 | 0.99% |
| 10 | SMTP | 57 | <0.01% | DNS.Canonical | 2,494 | 0.54% |

Top application categories: Unspecified 76.52%, Network 8.78%, System 7.10%, Web 6.76%, Download 0.72%, IoT-Scada 0.02%, RemoteAccess 0.01%, Email 0.01%, RPC 0.01%, Database 0.01%.

nDPI could not identify the application for 1,731,996 flows (76.52%); 1,731,413 of them (99.97%) have at most 2 packets, i.e. no payload to classify. 10,503 flows (0.46%) carry a guessed application. Of the 3,818 attack flows with another application name (most common: BitTorrent, Viber, VNC), 3,774 are flagged `application_is_guessed` (inferred from the port) and 3,756 are `nmap-full-portscan` probes.

### 7.3 Application metadata availability

| Field | Flows with a value | % of all | Attack | Benign |
| :--- | ---: | ---: | ---: | ---: |
| `requested_server_name` | 332,670 | 14.70% | 54,077 | 278,593 |
| `user_agent` | 143,361 | 6.33% | 54,051 | 89,310 |
| `content_type` | 126,740 | 5.60% | 54,027 | 72,713 |
| `client_fingerprint` | 167 | <0.01% | 142 | 25 |
| `server_fingerprint` | 87 | <0.01% | 62 | 25 |

## 8. Ports

Distinct destination ports: 65,535 over all flows, 65,534 in attack flows (22 excluding `nmap-full-portscan`), 6,992 in benign flows.

### 8.1 Destination ports of attack flows (excluding `nmap-full-portscan`)

| Port | Flows | % of targeted attack flows | Main classes |
| ---: | ---: | ---: | :--- |
| 80 | 53,555 | 75.92% | `ms2-mutillidae-sqlmap` (53,343), `ms3-iis-http-dos` (53), `ms2-dvwa-xss-reflected` (51) |
| 21 | 15,929 | 22.58% | `ms3-iis-ftp-wordlist` (15,924), `ms3-iis-ftp-wordlist-portscan` (5) |
| 10086 | 220 | 0.31% | `vulnhub-1panel-cve-2024-39907` (218), `vulnhub-1panel-cve-2024-39907-portscan` (2) |
| 8484 | 157 | 0.22% | `ms3-jenkins-revshell` (152), `ms3-jenkins-portscan` (5) |
| 4848 | 154 | 0.22% | `ms3-glassfish-revshell` (149), `ms3-glassfish-portscan` (5) |
| 9095 | 139 | 0.20% | `vulnhub-aj-report-cnvd-2024-15077` (133), `vulnhub-aj-report-cnvd-2024-15077-portscan` (6) |
| 8161 | 115 | 0.16% | `vulnhub-activemq-cve-2022-41678` (85), `vulnhub-activemq-cve-2026-34197` (21), `vulnhub-activemq-cve-2022-41678-portscan` (8) |
| 8080 | 91 | 0.13% | `vulnhub-airflow-cve-2020-17526` (42), `vulnhub-airflow-cve-2020-11978` (39), `ms3-glassfish-revshell` (3) |
| 8888 | 37 | 0.05% | `vulnhub-apache-druid-cve-2021-25646` (34), `vulnhub-apache-druid-cve-2021-25646-portscan` (3) |
| 9200 | 33 | 0.05% | `ms3-elasticsearch-revshell` (28), `ms3-elasticsearch-portscan` (5) |
| 6667 | 24 | 0.03% | `ms2-unrealircd-revshell` (18), `ms2-unrealircd-portscan` (6) |
| 8000 | 19 | 0.03% | `vulnhub-flask-ssti` (12), `vulnhub-flask-ssti-portscan` (7) |
| 513 | 15 | 0.02% | `ms2-rservices-portscan` (8), `ms2-rservices-revshell` (7) |
| 161 | 12 | 0.02% | `ms3-snmp-enum` (7), `ms3-snmp-portscan` (5) |
| 9080 | 11 | 0.02% | `vulnhub-apisix-cve-2020-13945` (9), `vulnhub-apisix-cve-2020-13945-portscan` (2) |

### 8.2 Service ports of benign flows

| Service port | Flows | % of benign | Main applications |
| ---: | ---: | ---: | :--- |
| 53 | 161,945 | 34.85% | DNS (96%), DNS.Microsoft (3%) |
| 123 | 146,251 | 31.48% | NTP (100%) |
| 9428 | 92,242 | 19.85% | HTTP (100%), Unknown (0%) |
| 0 | 25,946 | 5.58% | IGMP (99%), ICMP (1%) |
| 5355 | 10,167 | 2.19% | LLMNR (100%) |
| 138 | 8,546 | 1.84% | NetBIOS.SMBv1 (100%) |
| 137 | 5,708 | 1.23% | NetBIOS (100%) |
| 80 | 3,710 | 0.80% | HTTP (100%) |
| 443 | 2,428 | 0.52% | TLS (100%) |
| 54328 | 487 | 0.10% | Unknown (100%) |
| 58982 | 436 | 0.09% | Unknown (100%) |
| 58984 | 236 | 0.05% | Unknown (100%) |
| 110 | 118 | 0.03% | POP3 (100%) |
| 4444 | 54 | 0.01% | Unknown (100%) |
| 22 | 32 | <0.01% | SSH (100%) |

`service_port` is the well-known side of the flow (the lower port if neither or both are below 1024).

## 9. Hosts and network

| Metric | Value |
| :--- | :--- |
| Unique source IPs | 49 |
| Unique destination IPs | 133 |
| Unique IPs overall | 148 (139 IPv4, 9 IPv6) |
| Flows between two private (RFC 1918 / ULA) addresses | 2,072,607 (91.57%) |
| Flows with a public or multicast endpoint | 190,814 (8.43%) |
| Flows to a multicast address | 36,468 (1.61%) |
| Flows to the limited broadcast address | 0 |
| Public IPs pseudonymized (documentation ranges) | 92 addresses in 8,115 flows; kept unchanged: 194.149.136.252 |

### 9.1 Flows by host role

Roles come from the attack logs: *attacker* = an attacker's source IP, *target* = a logged target, *other* = everything else (gateway, infrastructure, other lab hosts).

| Source role | Destination role | Flows | % of all | Attack | Benign | Bytes | Main services (application:dst port) |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| attacker | target | 1,798,905 | 79.48% | 1,798,765 | 140 | 1.86 GB | HTTP:80 2.98%, FTP_CONTROL:21 0.89%, HTTP:10086 0.01% |
| target | other | 366,818 | 16.21% | 0 | 366,818 | 388.28 MB | DNS:53 35.82%, NTP:123 34.87%, HTTP:9428 21.04% |
| other | other | 97,131 | 4.29% | 0 | 97,131 | 79.04 MB | DNS:53 24.17%, NTP:123 18.88%, HTTP:9428 15.49% |
| target | attacker | 551 | 0.02% | 0 | 551 | 448.48 KB | HTTP:80 87.84%, Unknown:4444 9.62%, Unknown:4447 0.91% |
| other | target | 9 | <0.01% | 0 | 9 | 6.70 KB | ICMP:0 33.33%, Unknown:33342 11.11%, Unknown:37802 11.11% |
| attacker | other | 6 | <0.01% | 0 | 6 | 356.78 KB | SSH:22 83.33%, ICMP:0 16.67% |
| other | attacker | 1 | <0.01% | 0 | 1 | 206 B | Unknown:4444 100.00% |

Attack labels are assigned only to flows that start at an attacker host, so attack traffic appears as attacker → target. Traffic between targets and other hosts is background activity, and its main services are listed in the table. Section 5.6 explains the target → attacker flows and the benign attacker → target flows.

### 9.2 Top hosts by flow count

| Host | Role | Flows as source | Flows as destination | Total flows | Bytes |
| :--- | :--- | ---: | ---: | ---: | ---: |
| 192.168.71.206 | attacker (attacker_5) | 504,259 | 11 | 504,270 | 614.97 MB |
| 192.168.71.204 | attacker (attacker_2) | 349,495 | 497 | 349,992 | 396.98 MB |
| 192.168.71.203 | attacker (attacker_1) | 343,544 | 12 | 343,556 | 112.29 MB |
| 192.168.71.12 | attacker (attacker_7) | 311,085 | 10 | 311,095 | 173.63 MB |
| 192.168.77.252 | target (VulHub) | 1,566 | 264,827 | 266,393 | 37.56 MB |
| 192.168.71.201 | attacker (attacker_3) | 216,462 | 22 | 216,484 | 442.30 MB |
| 192.168.77.222 | target (Metasploitable 2) | 45,089 | 142,566 | 187,655 | 394.91 MB |
| 192.168.77.227 | target (Metasploitable 2) | 98,335 | 69,391 | 167,726 | 212.14 MB |
| 192.168.77.1 | other | 6 | 159,503 | 159,509 | 29.61 MB |
| 194.149.136.252 | other | 0 | 146,231 | 146,231 | 216.44 MB |
| 192.168.77.235 | target (VulHub) | 1,977 | 135,560 | 137,537 | 21.96 MB |
| 192.168.77.230 | target (VulHub) | 3,689 | 131,851 | 135,540 | 24.36 MB |
| 192.168.77.225 | target (Metasploitable 2) | 45,091 | 85,835 | 130,926 | 596.57 MB |
| 192.168.77.223 | target (Metasploitable 2) | 45,087 | 80,077 | 125,164 | 454.86 MB |
| 192.168.77.224 | target (Metasploitable 2) | 45,407 | 74,065 | 119,472 | 162.35 MB |

### 9.3 Subnet pairs

| Source subnet | Destination subnet | Flows | % of all | Attack | Benign |
| :--- | :--- | ---: | ---: | ---: | ---: |
| 192.168.71.0/24 | 192.168.77.0/24 | 1,806,047 | 79.79% | 1,798,765 | 7,282 |
| 192.168.77.0/24 | 192.168.77.0/24 | 173,763 | 7.68% | 0 | 173,763 |
| 192.168.77.0/24 | 194.149.136.0/24 | 146,231 | 6.46% | 0 | 146,231 |
| 192.168.77.0/24 | 192.168.85.0/24 | 92,234 | 4.07% | 0 | 92,234 |
| 192.168.77.0/24 | 224.0.0.0/24 | 30,766 | 1.36% | 0 | 30,766 |
| IPv6 | IPv6 | 5,212 | 0.23% | 0 | 5,212 |
| 192.168.77.0/24 | 192.0.2.0/24 | 5,093 | 0.23% | 0 | 5,093 |
| 192.168.77.0/24 | 198.51.100.0/24 | 1,565 | 0.07% | 0 | 1,565 |
| 192.168.77.0/24 | 203.0.113.0/24 | 1,457 | 0.06% | 0 | 1,457 |
| 192.168.77.0/24 | 192.168.71.0/24 | 552 | 0.02% | 0 | 552 |
| 192.168.77.0/24 | 224.2.2.0/24 | 487 | 0.02% | 0 | 487 |
| 192.168.85.0/24 | 192.168.77.0/24 | 8 | <0.01% | 0 | 8 |
| 192.168.77.0/24 | 10.10.5.0/24 | 3 | <0.01% | 0 | 3 |
| 169.254.182.0/24 | 224.0.0.0/24 | 2 | <0.01% | 0 | 2 |
| 169.254.214.0/24 | 224.0.0.0/24 | 1 | <0.01% | 0 | 1 |

## 10. Time

### 10.1 Flows per day

| Date (flow start) | Capture | Flows | Attack | Benign | Attack % | Main attack classes |
| :--- | :--- | ---: | ---: | ---: | ---: | :--- |
| 2026-07-14 | 07 | 82,836 | 0 | 82,836 | 0% |  |
| 2026-07-15 | 07 | 564,183 | 441,692 | 122,491 | 78.29% | `nmap-full-portscan` (397,494), `ms2-mutillidae-sqlmap` (43,899) |
| 2026-07-16 | 07 | 1,094,740 | 962,859 | 131,881 | 87.95% | `nmap-full-portscan` (944,966), `ms3-iis-ftp-wordlist` (15,302) |
| 2026-07-17 | 07 | 54,696 | 9,115 | 45,581 | 16.66% | `nmap-full-portscan` (9,115) |
| 2026-10-01 | 10 | 140,329 | 131,676 | 8,653 | 93.83% | `nmap-full-portscan` (131,411), `vulnhub-1panel-cve-2024-39907` (129) |
| 2026-10-02 | 10 | 197,145 | 178,703 | 18,442 | 90.65% | `nmap-full-portscan` (174,896), `ms2-mutillidae-sqlmap` (3,782) |
| 2026-10-03 | 10 | 19,180 | 658 | 18,522 | 3.43% | `ms3-iis-ftp-wordlist` (522), `ms3-jenkins-revshell` (100) |
| 2026-10-04 | 10 | 18,420 | 0 | 18,420 | 0% |  |
| 2026-10-05 | 10 | 80,204 | 74,062 | 6,142 | 92.34% | `nmap-full-portscan` (70,332), `ms2-mutillidae-sqlmap` (3,729) |
| 2026-10-06 | 10 | 1,582 | 0 | 1,582 | 0% |  |
| 2026-10-07 | 10 | 1,582 | 0 | 1,582 | 0% |  |
| 2026-10-08 | 10 | 1,583 | 0 | 1,583 | 0% |  |
| 2026-10-09 | 10 | 1,593 | 0 | 1,593 | 0% |  |
| 2026-10-10 | 10 | 1,584 | 0 | 1,584 | 0% |  |
| 2026-10-11 | 10 | 1,612 | 0 | 1,612 | 0% |  |
| 2026-10-12 | 10 | 1,578 | 0 | 1,578 | 0% |  |
| 2026-10-13 | 10 | 574 | 0 | 574 | 0% |  |

### 10.2 Hour of day

<details>
<summary>Flows by hour of day (UTC)</summary>

| Hour (UTC) | Flows | Attack | Benign | Attack % |
| :--- | ---: | ---: | ---: | ---: |
| 00:00 | 157,130 | 138,604 | 18,526 | 88.21% |
| 01:00 | 24,982 | 4,972 | 20,010 | 19.90% |
| 02:00 | 154,677 | 136,071 | 18,606 | 87.97% |
| 03:00 | 21,455 | 1,500 | 19,955 | 6.99% |
| 04:00 | 19,864 | 1,525 | 18,339 | 7.68% |
| 05:00 | 92,516 | 72,535 | 19,981 | 78.40% |
| 06:00 | 23,048 | 3,011 | 20,037 | 13.06% |
| 07:00 | 90,373 | 66,540 | 23,833 | 73.63% |
| 08:00 | 158,219 | 135,386 | 22,833 | 85.57% |
| 09:00 | 88,004 | 69,107 | 18,897 | 78.53% |
| 10:00 | 91,399 | 73,839 | 17,560 | 80.79% |
| 11:00 | 84,824 | 65,757 | 19,067 | 77.52% |
| 12:00 | 151,449 | 133,868 | 17,581 | 88.39% |
| 13:00 | 19,098 | 18 | 19,080 | 0.09% |
| 14:00 | 150,132 | 131,860 | 18,272 | 87.83% |
| 15:00 | 85,605 | 65,848 | 19,757 | 76.92% |
| 16:00 | 86,726 | 68,483 | 18,243 | 78.96% |
| 17:00 | 164,610 | 144,860 | 19,750 | 88.00% |
| 18:00 | 92,367 | 74,085 | 18,282 | 80.21% |
| 19:00 | 106,980 | 87,140 | 19,840 | 81.45% |
| 20:00 | 154,920 | 136,700 | 18,220 | 88.24% |
| 21:00 | 203,814 | 184,077 | 19,737 | 90.32% |
| 22:00 | 19,992 | 1,492 | 18,500 | 7.46% |
| 23:00 | 21,237 | 1,487 | 19,750 | 7.00% |

</details>

### 10.3 Class timeline

<details>
<summary>First and last flow of each of the 53 attack classes</summary>

| Label | Capture(s) | First flow | Last flow | Days with flows |
| :--- | :--- | :--- | :--- | :--- |
| `nmap-full-portscan` | 07, 10 | 2026-07-15 12:22 | 2026-10-05 05:57 | 7 |
| `ms2-rservices-portscan` | 07, 10 | 2026-07-15 12:23 | 2026-10-02 20:23 | 3 |
| `ms2-unrealircd-portscan` | 07 | 2026-07-15 12:40 | 2026-07-16 00:11 | 2 |
| `ms2-rservices-revshell` | 07, 10 | 2026-07-15 12:43 | 2026-10-02 20:23 | 3 |
| `ms2-unrealircd-revshell` | 07, 10 | 2026-07-15 12:46 | 2026-10-02 20:31 | 3 |
| `ms2-dvwa-xss-reflected-portscan` | 07, 10 | 2026-07-15 12:52 | 2026-10-02 20:32 | 3 |
| `ms3-glassfish-revshell` | 07, 10 | 2026-07-15 12:52 | 2026-10-03 19:16 | 3 |
| `ms2-dvwa-xss-reflected` | 07, 10 | 2026-07-15 12:52 | 2026-10-02 20:34 | 3 |
| `ms2-dvwa-xss-stored-portscan` | 07 | 2026-07-15 13:05 | 2026-07-16 00:22 | 2 |
| `ms2-dvwa-xss-stored` | 07 | 2026-07-15 13:05 | 2026-07-16 00:25 | 2 |
| `ms2-dvwa-cmdinject` | 07 | 2026-07-15 16:41 | 2026-07-16 00:27 | 2 |
| `ms2-dvwa-cmdinject-portscan` | 07 | 2026-07-15 16:41 | 2026-07-16 00:26 | 2 |
| `ms2-dvwa-lfi-portscan` | 07 | 2026-07-15 16:44 | 2026-07-16 00:27 | 2 |
| `ms2-dvwa-lfi` | 07 | 2026-07-15 16:45 | 2026-07-15 21:31 | 1 |
| `ms2-dvwa-sqli-manual-portscan` | 07 | 2026-07-15 16:46 | 2026-07-16 00:29 | 2 |
| `ms2-dvwa-sqli-manual` | 07 | 2026-07-15 16:46 | 2026-07-16 00:35 | 2 |
| `ms2-mutillidae-sqlmap-portscan` | 07, 10 | 2026-07-15 16:48 | 2026-10-05 05:57 | 4 |
| `ms2-mutillidae-sqlmap` | 07, 10 | 2026-07-15 16:50 | 2026-10-05 06:11 | 4 |
| `ms3-glassfish-portscan` | 07, 10 | 2026-07-15 19:06 | 2026-10-03 19:11 | 3 |
| `ms3-jenkins-portscan` | 07, 10 | 2026-07-15 19:22 | 2026-10-03 19:17 | 3 |
| `ms3-iis-ftp-wordlist-portscan` | 07, 10 | 2026-07-15 19:26 | 2026-10-03 20:27 | 3 |
| `ms3-iis-ftp-wordlist` | 07, 10 | 2026-07-15 19:27 | 2026-10-03 20:32 | 3 |
| `ms3-elasticsearch-portscan` | 07, 10 | 2026-07-15 19:29 | 2026-10-03 20:33 | 3 |
| `ms3-elasticsearch-revshell` | 07, 10 | 2026-07-15 19:30 | 2026-10-03 20:35 | 3 |
| `ms3-snmp-portscan` | 07, 10 | 2026-07-15 19:32 | 2026-10-03 20:36 | 3 |
| `ms3-snmp-enum` | 07, 10 | 2026-07-15 19:33 | 2026-10-03 20:36 | 3 |
| `ms3-jmx-portscan` | 07, 10 | 2026-07-15 19:34 | 2026-10-03 20:36 | 3 |
| `ms3-jmx-revshell` | 07 | 2026-07-15 19:36 | 2026-07-16 10:55 | 2 |
| `ms3-jenkins-revshell` | 07, 10 | 2026-07-15 22:01 | 2026-10-03 19:21 | 3 |
| `ms3-iis-http-dos-portscan` | 07 | 2026-07-16 01:56 | 2026-07-16 14:48 | 1 |
| `ms3-iis-http-dos` | 07 | 2026-07-16 01:57 | 2026-07-16 14:53 | 1 |
| `vulnhub-flask-ssti-portscan` | 07 | 2026-07-16 02:02 | 2026-07-16 17:56 | 1 |
| `vulnhub-aj-report-cnvd-2024-15077-portscan` | 07, 10 | 2026-07-16 02:11 | 2026-10-01 14:49 | 2 |
| `vulnhub-aj-report-cnvd-2024-15077` | 07, 10 | 2026-07-16 02:12 | 2026-10-01 15:16 | 2 |
| `vulnhub-airflow-cve-2020-17526-portscan` | 07 | 2026-07-16 08:32 | 2026-07-16 18:04 | 1 |
| `vulnhub-airflow-cve-2020-17526` | 07 | 2026-07-16 08:37 | 2026-07-16 18:13 | 1 |
| `vulnhub-activemq-cve-2022-41678-portscan` | 07, 10 | 2026-07-16 08:51 | 2026-10-01 15:15 | 2 |
| `vulnhub-airflow-cve-2020-11981-portscan` | 07 | 2026-07-16 10:56 | 2026-07-16 10:56 | 1 |
| `vulnhub-airflow-cve-2020-11981` | 07 | 2026-07-16 12:30 | 2026-07-16 13:54 | 1 |
| `vulnhub-1panel-cve-2024-39907-portscan` | 07, 10 | 2026-07-16 13:55 | 2026-10-01 14:47 | 2 |
| `vulnhub-1panel-cve-2024-39907` | 07, 10 | 2026-07-16 14:03 | 2026-10-01 14:50 | 2 |
| `vulnhub-flask-ssti` | 07 | 2026-07-16 14:07 | 2026-07-16 14:33 | 1 |
| `vulnhub-apache-cxf-cve-2024-28752-portscan` | 07 | 2026-07-16 14:22 | 2026-07-16 14:22 | 1 |
| `vulnhub-apache-cxf-cve-2024-28752` | 07 | 2026-07-16 14:23 | 2026-07-16 14:33 | 1 |
| `vulnhub-activemq-cve-2026-34197-portscan` | 07 | 2026-07-16 14:28 | 2026-07-16 14:28 | 1 |
| `vulnhub-activemq-cve-2026-34197` | 07 | 2026-07-16 14:31 | 2026-07-16 14:39 | 1 |
| `vulnhub-apache-druid-cve-2021-25646-portscan` | 07, 10 | 2026-07-16 14:40 | 2026-10-01 15:13 | 2 |
| `vulnhub-apache-druid-cve-2021-25646` | 07, 10 | 2026-07-16 14:42 | 2026-10-02 20:13 | 3 |
| `vulnhub-activemq-cve-2022-41678` | 07, 10 | 2026-07-16 16:54 | 2026-10-02 20:06 | 3 |
| `vulnhub-airflow-cve-2020-11978-portscan` | 07 | 2026-07-16 17:57 | 2026-07-16 17:57 | 1 |
| `vulnhub-airflow-cve-2020-11978` | 07 | 2026-07-16 17:57 | 2026-07-16 18:07 | 1 |
| `vulnhub-apisix-cve-2020-13945-portscan` | 07, 10 | 2026-07-16 18:02 | 2026-10-01 14:43 | 2 |
| `vulnhub-apisix-cve-2020-13945` | 07, 10 | 2026-07-16 18:03 | 2026-10-01 14:50 | 2 |

</details>

## 11. Data quality and integrity

| Check | Result |
| :--- | :--- |
| Duplicate `flow_id` | 0 |
| Duplicate (canonical key, first-seen) rows | 0 |
| Failed pcap files during extraction | 0 |
| Packets lost while stitching fragments into flows | 0 |
| Impossible values: negative duration | 0 |
| Impossible values: zero packet flows | 0 |
| Impossible values: zero byte flows | 0 |
| Impossible values: first seen before capture | 0 |
| Impossible values: last seen after capture | 0 |
| Impossible values: last before first | 0 |
| Stitched flows (repaired across 10-min file boundaries) | 2,422 (max 3 fragments) |
| Flows re-cut at the active timeout | 0 |
| Flows possibly cut at the start / end of a capture | 192 / 174 |
| Negative or zero durations | 0 negative, 1,415,769 zero (single-packet or same-millisecond flows) |

Capture gaps longer than 30 s between consecutive packets across pcap files: capture 10 after 2026-10-08 04:59 (56.5 s); capture 10 after 2026-10-08 09:49 (42.2 s). All gaps are shorter than the 120 s idle timeout, so flows were still stitched across them.

### 11.1 Missing values

| Column | Null values | % of rows |
| :--- | ---: | ---: |
| `bytes_ratio_updown` | 64,619 | 2.85% |
| `packets_ratio_updown` | 64,619 | 2.85% |
| `bidirectional_pps` | 1,415,769 | 62.55% |
| `bidirectional_bps` | 1,415,769 | 62.55% |
| `src2dst_pps` | 1,933,924 | 85.44% |
| `src2dst_bps` | 1,933,924 | 85.44% |
| `dst2src_pps` | 1,956,985 | 86.46% |
| `dst2src_bps` | 1,956,985 | 86.46% |
| `splt_*_i` (57 columns) | 41,474 – 2,188,610 | 1.83% – 96.69% |

Nulls are structural, not data loss. `splt_*_i` is empty when the flow has ≤ i packets. Rates (`*_pps`, `*_bps`) are empty when the duration is 0 ms. Ratios are empty when the reverse direction carried nothing. Text metadata columns use the empty string instead of null (section 7.3).

## 12. Features (columns)

| Column group | Columns | Examples |
| :--- | ---: | :--- |
| Early-packet sequence (SPLT, first 20 packets) | 63 | `splt_direction`, `splt_ps`, `splt_piat_ms`, `splt_direction_0`, … |
| TCP flag counters | 24 | `bidirectional_syn_packets`, `bidirectional_cwr_packets`, `bidirectional_ece_packets`, `bidirectional_urg_packets`, … |
| Identity and keys | 16 | `id`, `expiration_id`, `src_ip`, `src_mac`, … |
| Timing | 14 | `bidirectional_first_seen_ms`, `bidirectional_last_seen_ms`, `bidirectional_duration_ms`, `src2dst_first_seen_ms`, … |
| Volume and rates | 14 | `bidirectional_packets`, `bidirectional_bytes`, `src2dst_packets`, `src2dst_bytes`, … |
| Address / port / protocol flags | 14 | `is_ipv4`, `is_ipv6`, `is_tcp`, `is_udp`, … |
| Packet-size statistics | 12 | `bidirectional_min_ps`, `bidirectional_mean_ps`, `bidirectional_stddev_ps`, `bidirectional_max_ps`, … |
| Inter-arrival-time statistics | 12 | `bidirectional_min_piat_ms`, `bidirectional_mean_piat_ms`, `bidirectional_stddev_piat_ms`, `bidirectional_max_piat_ms`, … |
| Application / nDPI | 9 | `application_name`, `application_category_name`, `application_is_guessed`, `application_confidence`, … |
| Provenance and stitching | 8 | `fragment_id`, `source_pcap`, `n_fragments`, `fragment_ids`, … |
| Dataset (capture, label) | 2 | `capture_id`, `label` |

The three list columns `splt_direction`, `splt_ps`, `splt_piat_ms` hold the same SPLT values as the flat `splt_*_0..19` columns, serialized as JSON arrays. The full meaning, unit and type of every column is in `flow-extraction/DATA_DICTIONARY.md`.

### 12.1 Constant columns

These columns hold a single value across the whole dataset and carry no information for a model:

| Column | Value |
| :--- | :--- |
| `expiration_id` | 0 |
| `src_oui` | '00:50:56' |
| `vlan_id` | 1017 |
| `bidirectional_cwr_packets` | 0 |
| `bidirectional_ece_packets` | 0 |
| `src2dst_cwr_packets` | 0 |
| `src2dst_ece_packets` | 0 |
| `src2dst_urg_packets` | 0 |
| `dst2src_cwr_packets` | 0 |
| `dst2src_ece_packets` | 0 |
| `recut_active_timeout` | False |
| `src_is_multicast` | False |
| `src_is_broadcast` | False |
| `dst_is_broadcast` | False |
| `splt_direction_0` | 0 |
| `splt_piat_ms_0` | 0.0 |

### 12.2 Identifying columns

These columns identify the flow, host, capture or absolute time rather than describe behaviour. A model trained on them learns the lab setup (e.g. which IPs were attackers, or when attacks happened) instead of attack traffic. Exclude them from model inputs unless that is intended. Keep them for joins, splits and error analysis.

`flow_id`, `id`, `fragment_id`, `fragment_ids`, `canonical_key`, `source_pcap`, `source_pcaps`, `expiration_id`, `src_ip`, `dst_ip`, `src_mac`, `dst_mac`, `src_oui`, `dst_oui`, `start_date`, `start_hour`, `start_minute`, `start_day_of_week`, `capture_id`, plus the absolute timestamps `*_first_seen_ms` / `*_last_seen_ms`. Ports (`src_port`, `dst_port`, `service_port`) are legitimate features, but the attacker's ephemeral source port is effectively random.

## 13. Provenance and configuration

| Setting | Capture 07 | Capture 10 |
| :--- | :--- | :--- |
| Extraction run (UTC) | 2026-10-23 12:46 | 2026-10-23 13:03 |
| python version | 3.12.3 | 3.12.3 |
| nfstream version | 6.6.0 | 6.6.0 |
| pandas version | 3.0.5 | 3.0.5 |
| pyarrow version | 25.0.1 | 25.0.1 |
| NFStream `decode_tunnels` | True | True |
| NFStream `promiscuous_mode` | False | False |
| NFStream `statistical_analysis` | True | True |
| NFStream `splt_analysis` | 20 | 20 |
| NFStream `n_dissections` | 20 | 20 |
| NFStream `accounting_mode` | 0 | 0 |
| NFStream `idle_timeout` | 120 | 120 |
| NFStream `active_timeout` | 1800 | 1800 |
| NFStream `n_meters` | 1 | 1 |
| Byte accounting | 0 = link-layer (L2) bytes per packet | 0 = link-layer (L2) bytes per packet |
| Stddev convention | sample stddev (ddof=1) | sample stddev (ddof=1) |
| Labeling time tolerance | ±1000 ms | ±1000 ms |
| Tuple fallback | True | True |
| Benign label | BENIGN | BENIGN |
| Attack logs | attacker_1.json, attacker_2.json, attacker_3.json, attacker_5.json | attacker_4.json, attacker_7.json |
| Manual overrides (unified dataset only) | 11 | 5 |

Anonymization (release only): public IPs -> random, persistent pseudonyms in documentation ranges (RFC 5737 / RFC 3849); private, multicast and special-purpose addresses unchanged. 92 public addresses pseudonymized; kept unchanged: 194.149.136.252.

Pipeline: `flow-extraction` (NFStream per pcap → stitching across file boundaries → derived columns → validation → CSV), then `flow-labeling/label_flows.py`, then `dataset-unification/build_dataset.py` (unifies the captures and applies the overrides), then `dataset-analysis/analyze_dataset.py` (writes this file).

