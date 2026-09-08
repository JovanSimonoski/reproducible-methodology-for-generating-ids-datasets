# Attack ditribution on Vulhub Machines


| VM | Attacks available (`attack_name`) | # | Port |
|---|---|---|---|
| **VM-1** | `vulnhub-flask-ssti` | 16 | 8000 |
| | `vulnhub-airflow-cve-2020-11978` | 17 | 8080 |
| | `vulnhub-apache-druid-cve-2021-25646` | 25 | 8888 |
| | `vulnhub-apisix-cve-2020-13945` | 26 | 9080 |
| **VM-2** | `vulnhub-airflow-cve-2020-17526` | 22 | 8080 |
| | `vulnhub-activemq-cve-2022-41678` | 20 | 8161 |
| | `vulnhub-aj-report-cnvd-2024-15077` | 23 | 9095 |
| **VM-3** | `vulnhub-airflow-cve-2020-11981` | 18 | 6379 |
| | `vulnhub-1panel-cve-2024-39907` | 19 | 10086 |
| | `vulnhub-flask-ssti` | 16 | 8000 |
| **VM-4** | `vulnhub-apache-cxf-cve-2024-28752` | 24 | 8080 |
| | `vulnhub-activemq-cve-2026-34197` | 21 | 8161 |
| | `vulnhub-apache-druid-cve-2021-25646` | 25 | 8888 |
| **VM-5** | `vulnhub-apisix-cve-2020-13945` | 26 | 9080 |
| | `vulnhub-aj-report-cnvd-2024-15077` | 23 | 9095 |
| | `vulnhub-1panel-cve-2024-39907` | 19 | 10086 |
| **VM-6** | `vulnhub-apache-druid-cve-2021-25646` | 25 | 8888 |
| | `vulnhub-activemq-cve-2022-41678` | 20 | 8161 |
| | ~~`vulnhub-flask-ssti`~~ *(unavailable — broken image)* | 16 | 8000 |
| **VM-7** | `vulnhub-apisix-cve-2020-13945` | 26 | 9080 |
| | `vulnhub-1panel-cve-2024-39907` | 19 | 10086 |
| | `vulnhub-aj-report-cnvd-2024-15077` | 23 | 9095 |


# Configuration

## Install docker

```
# Add Docker's official GPG key:
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
```

```
# Add the repository to Apt sources:
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
```

```
sudo apt update
```

```
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

```
# Add current user to docker group (re-login afterwards)
sudo usermod -aG docker "$USER"
```

## Clone the repo

```
git clone --depth 1 https://github.com/vulhub/vulhub.git ~/vulhub && \
cd ~/vulhub && \
git fetch --depth 1 origin d277a8693e588684e951dddb0733809e53881a3c && \
git checkout d277a8693e588684e951dddb0733809e53881a3c && \
git rev-parse HEAD
```

## NTP config

```
sudo sed -i 's/^#\?NTP=.*/NTP=ntp.finki.ukim.mk/' /etc/systemd/timesyncd.conf
sudo systemctl restart systemd-timesyncd
timedatectl status
```

## Container configuration

## VulHub Path Reference
 
| Container (attack name) | VulHub path | Host port(s) |
|---|---|---|
| `vulnhub-flask-ssti` | `flask/ssti` | 8000 |
| `vulnhub-airflow-cve-2020-11978` | `airflow/CVE-2020-11978` | 8080 (webserver) + 5555 (Flower) |
| `vulnhub-airflow-cve-2020-11981` | `airflow/CVE-2020-11981` | 8080 (webserver) + 5555 (Flower) + 6379 (Redis = attack target) |
| `vulnhub-airflow-cve-2020-17526` | `airflow/CVE-2020-17526` | 8080 (webserver) + 5555 (Flower) |
| `vulnhub-apache-cxf-cve-2024-28752` | `apache-cxf/CVE-2024-28752` | 8080 |
| `vulnhub-activemq-cve-2022-41678` | `activemq/CVE-2022-41678` | 8161 |
| `vulnhub-activemq-cve-2026-34197` | `activemq/CVE-2026-34197` | 8161 |
| `vulnhub-apache-druid-cve-2021-25646` | `apache-druid/CVE-2021-25646` | 8888 |
| `vulnhub-apisix-cve-2020-13945` | `apisix/CVE-2020-13945` | 9080 |
| `vulnhub-aj-report-cnvd-2024-15077` | `aj-report/CNVD-2024-15077` | 9095 |
| `vulnhub-1panel-cve-2024-39907` | `1panel/CVE-2024-39907` | 10086 |
 
> Airflow stacks require `docker compose run --rm airflow-init` before `docker compose up -d`.
 
---
 
## Allocation Overview
 
| VM | 8080 owner | Other containers |
|---|---|---|
| **VM-1** | airflow-11978 | flask (8000), druid (8888), apisix (9080) |
| **VM-2** | airflow-17526 | activemq-41678 (8161), aj-report (9095) |
| **VM-3** | airflow-11981 | 1panel (10086), flask (8000) |
| **VM-4** | cxf-28752 | activemq-34197 (8161), druid (8888) |
| **VM-5** | — | apisix (9080), aj-report (9095), 1panel (10086) |
| **VM-6** | — | flask (8000), druid (8888), activemq-41678 (8161) |
| **VM-7** | — | apisix (9080), 1panel (10086), aj-report (9095) |
 
No VM runs two Airflow stacks. No VM has two containers on the same host port. On VM-3, airflow-11981 owns 8080 (webserver, unused by the attack) and 6379 (Redis, the actual target) — no conflict since it is the only 8080 owner there.
 
> **Flower (port 5555):** Every Airflow stack also publishes 5555 (Celery Flower UI). Because each Airflow stack is isolated on its own VM (VM-1, VM-2, VM-3), 5555 never collides. Be aware it shows as an open port on those three VMs during a full port scan; it is not in the Attacks list, so traffic to it labels as benign — which is correct.
 
---
 
## Resource Note
 
Airflow stacks are heavy (webserver + scheduler + worker + Redis). Budget ~6-8 GB RAM on VMs running an Airflow stack (VM-1, VM-2, VM-3). VM-5/6/7 are light.
 
---
 
## VM-1 — airflow-11978
 
**Ports:** 8080 (airflow-11978), 8000 (flask), 8888 (druid), 9080 (apisix)
 
```bash
cd ~/vulhub
( cd flask/ssti && docker compose up -d )                    # :8000
( cd apache-druid/CVE-2021-25646 && docker compose up -d )   # :8888
( cd apisix/CVE-2020-13945 && docker compose up -d )         # :9080
( cd airflow/CVE-2020-11978 && docker compose run --rm airflow-init && docker compose up -d )  # :8080
```
 
**Verify:**
```bash
docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}'
for p in 8000 8080 5555 8888 9080; do
  echo -n "port $p: "; ss -ltn "sport = :$p" | grep -q LISTEN && echo OK || echo MISSING
done
```
 
---
 
## VM-2 — airflow-17526
 
**Ports:** 8080 (airflow-17526), 8161 (activemq-41678), 9095 (aj-report)
 
```bash
cd ~/vulhub
( cd activemq/CVE-2022-41678 && docker compose up -d )       # :8161
( cd aj-report/CNVD-2024-15077 && docker compose up -d )     # :9095
( cd airflow/CVE-2020-17526 && docker compose run --rm airflow-init && docker compose up -d )  # :8080
```
 
**Verify:**
```bash
docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}'
for p in 8080 5555 8161 9095; do
  echo -n "port $p: "; ss -ltn "sport = :$p" | grep -q LISTEN && echo OK || echo MISSING
done
```
 
---
 
## VM-3 — airflow-11981
 
**Ports:** 8080 + 6379 (airflow-11981; 6379 Redis is the attack target), 10086 (1panel), 8000 (flask)
 
```bash
cd ~/vulhub
( cd flask/ssti && docker compose up -d )                    # :8000
( cd 1panel/CVE-2024-39907 && docker compose up -d )         # :10086
( cd airflow/CVE-2020-11981 && docker compose run --rm airflow-init && docker compose up -d )  # :8080 + :6379
```
 
**Verify:**
```bash
docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}'
for p in 8000 6379 8080 5555 10086; do
  echo -n "port $p: "; ss -ltn "sport = :$p" | grep -q LISTEN && echo OK || echo MISSING
done
```
 
---
 
## VM-4 — cxf-28752
 
**Ports:** 8080 (cxf), 8161 (activemq-34197), 8888 (druid)
 
```bash
cd ~/vulhub
( cd activemq/CVE-2026-34197 && docker compose up -d )       # :8161
( cd apache-druid/CVE-2021-25646 && docker compose up -d )   # :8888
( cd apache-cxf/CVE-2024-28752 && docker compose up -d )     # :8080
```
 
**Verify:**
```bash
docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}'
for p in 8080 8161 8888; do
  echo -n "port $p: "; ss -ltn "sport = :$p" | grep -q LISTEN && echo OK || echo MISSING
done
```
 
---
 
## VM-5 — light
 
**Ports:** 9080 (apisix), 9095 (aj-report), 10086 (1panel)
 
```bash
cd ~/vulhub
( cd apisix/CVE-2020-13945 && docker compose up -d )         # :9080
( cd aj-report/CNVD-2024-15077 && docker compose up -d )     # :9095
( cd 1panel/CVE-2024-39907 && docker compose up -d )         # :10086
```
 
**Verify:**
```bash
docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}'
for p in 9080 9095 10086; do
  echo -n "port $p: "; ss -ltn "sport = :$p" | grep -q LISTEN && echo OK || echo MISSING
done
```
 
---
 
## VM-6 — light
 
**Ports:** 8000 (flask), 8888 (druid), 8161 (activemq-41678)
 
```bash
cd ~/vulhub
# ( cd flask/ssti && docker compose up -d ) WASN'T WORKING 
( cd apache-druid/CVE-2021-25646 && docker compose up -d )   # :8888
( cd activemq/CVE-2022-41678 && docker compose up -d )       # :8161
```
 
**Verify:**
```bash
docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}'
for p in 8000 8161 8888; do
  echo -n "port $p: "; ss -ltn "sport = :$p" | grep -q LISTEN && echo OK || echo MISSING
done
```
 
---
 
## VM-7 — light
 
**Ports:** 9080 (apisix), 10086 (1panel), 9095 (aj-report)
 
```bash
cd ~/vulhub
( cd apisix/CVE-2020-13945 && docker compose up -d )         # :9080
( cd 1panel/CVE-2024-39907 && docker compose up -d )         # :10086
( cd aj-report/CNVD-2024-15077 && docker compose up -d )     # :9095
```
 
**Verify:**
```bash
docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}'
for p in 9080 9095 10086; do
  echo -n "port $p: "; ss -ltn "sport = :$p" | grep -q LISTEN && echo OK || echo MISSING
done
```
 
---
 
## Teardown (any VM)
 
```bash
cd ~/vulhub
for d in $(find . -name docker-compose.yml -exec dirname {} \;); do
  ( cd "$d" && docker compose down -v 2>/dev/null )
done
docker rm -f $(docker ps -aq) 2>/dev/null   # brute-force fallback
```
 
---
 
## Credentials Quick Reference
 
| Service | URL | Credentials |
|---|---|---|
| ActiveMQ (both CVEs) | `http://<vm-ip>:8161` | `admin` / `admin` |
| 1Panel | `http://<vm-ip>:10086/entrance` | `1panel` / `1panel_password` |
| AJ-Report | `http://<vm-ip>:9095` | auth-bypass (no login) |
| Airflow 17526 | `http://<vm-ip>:8080` | session-forge (no login) |
| Druid | `http://<vm-ip>:8888` | none |
| APISIX | `http://<vm-ip>:9080` | API token `edd1c9f034335f136f87ad84b625c8f1` |
 
---