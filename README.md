# Awesome Offensive MCP Servers [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)



> **"I built this because I needed it."**

>

> This is a personal collection of **Model Context Protocol (MCP)** servers that I find useful for **Red Teaming, Pentesting, and Vulnerability Research**.

> While these tools are curated for my own workflows, I'm sharing them for anyone who wants to integrate Agentic AI into their offensive security stack.



---



## ⚠️ Disclaimer & Criteria



* **Criteria:** I only add tools that meet one of the following:

    1.  **30+ GitHub Stars** (Community verified)

    2.  **Personally Verified**

    3.  **Official Implementation** (Maintained by the vendor)

* **Responsibility:** The use of the tools and servers listed in this repository is strictly for **educational and authorized testing purposes only**. The maintainers assume **no responsibility** for any misuse or damage caused by these tools. You are responsible for complying with all applicable laws and regulations.

* **Safety:** **Always audit the code** of MCP servers before connecting them to your environment, especially those capable of executing commands or reading files.



---



## 🚀 What is MCP?



**Model Context Protocol (MCP)** is an open standard that acts as a universal translator between AI models (like Claude, Gemini) and your local tools. It allows AI to safely query databases, execute scripts, and interact with APIs without hardcoded integrations.



For offensive security, this means your AI agent can now **run Nmap scans, analyze Ghidra decompilation, and query Shodan**—all within a single conversation context.



---



## 📑 Categories



- [🕵️ Reconnaissance & OSINT](#recon)

- [🔬 Vulnerability Research & Analysis](#vuln)

- [🌐 Web, Network & Protocol](#web)

- [⚔️ Weaponization & Exploitation](#weapon)

- [🔓 Cryptography & Cracking](#crypto)

- [🏴 Post-Exploitation & Active Directory](#postexp)

- [🏗️ Infrastructure, Utils & Orchestration](#infra)



---



<div id="recon"></div>

## 🕵️ Reconnaissance & OSINT

*Tools for asset discovery, threat intelligence gathering, and external attack surface mapping.*



- [**Nmap MCP**](https://github.com/vorotaai/nmap-mcp) – Run Nmap scans (host discovery, port scanning, OS/service detection, NSE scripts) via natural language.

- [**Shodan MCP**](https://github.com/BurtTheCoder/mcp-shodan) – AI access to Shodan search, host information, and CVEs.

- [**VirusTotal MCP**](https://github.com/BurtTheCoder/mcp-virustotal) – Query VT scans, analyze URLs, IP addresses, and file hashes.

- [**ExternalAttacker MCP**](https://github.com/MorDavid/ExternalAttacker-MCP) – Maps external attack surfaces using ProjectDiscovery tools (subfinder, httpx, etc.).

- [**NetworksDB MCP**](https://github.com/MorDavid/NetworksDB-MCP) – Lookup IP ranges, ASNs, and DNS records.

- [**AlienVault OTX MCP**](https://github.com/mrwadams/otx-mcp) – Interface to OTX threat intelligence feeds.

- [**ZoomEye MCP**](https://github.com/zoomeye-ai/mcp_zoomeye) – Retrieve cyberspace assets and dorks via ZoomEye API.

- [**GitHub MCP Server**](https://github.com/github/github-mcp-server) – Full GitHub API access. Great for **Secret Scanning** and repository analysis.

- [**FastDomainCheck MCP**](https://github.com/bingal/FastDomainCheck-MCP-Server) – High-speed bulk domain availability checking.

- [**DNStwist MCP**](https://github.com/BurtTheCoder/mcp-dnstwist) – Detect phishing, typo-squatting, and attack domains.

- [**Maigret MCP**](https://github.com/BurtTheCoder/mcp-maigret) – Collect a dossier on a person by username across thousands of sites.

- [**Crunchbase MCP**](https://github.com/Cyreslab-AI/crunchbase-mcp-server) – Access Crunchbase organization data for corporate reconnaissance.

- [**ADEO CTI MCP**](https://github.com/ADEOSec/mcp-shodan) – A combo MCP for Shodan and VirusTotal threat analysis.

- [**Everything Search MCP**](https://github.com/mamertofabian/mcp-everything-search) – Fast local file search (Windows) for gathering internal intelligence.

- [**ANNA's MCP**](https://github.com/iosifache/annas-mcp) – Search and download documents/papers from Anna's Archive.

- [**MalwareBazaar MCP**](https://github.com/mytechnotalent/MalwareBazaar_MCP) – Interface with Malware Bazaar for real-time threat intel and sample metadata.

- [**MITRE ATT&CK MCP**](https://github.com/stoyky/mitre-attack-mcp) – Query and interact with the MITRE ATT&CK framework data.



---



<div id="vuln"></div>

## 🔬 Vulnerability Research & Analysis

*Tools for static analysis, reverse engineering, mobile app analysis, and firmware inspection.*



- [**Ghidra MCP**](https://github.com/LaurieWired/GhidraMCP) – Deep integration with Ghidra for autonomous reverse engineering and function explanation.

- [**Ghidra MCP Alternative**](https://github.com/Bamimore-Tomi/ghidra_mcp) – Another variant of Ghidra MCP focusing on binary analysis capabilities.

- [**pyghidra-mcp**](https://github.com/clearbluejar/pyghidra-mcp) – Headless-first and GUI-capable Ghidra MCP server. Supports project-wide analysis and cross-binary tracing using Python.

- [**IDA Pro MCP**](https://github.com/mrexodia/ida-pro-mcp) – Control IDA Pro using LLMs for decompilation and analysis.

- [**Binary Ninja MCP**](https://github.com/MCPPhalanx/binaryninja-mcp) – Plugin to integrate AI workflows directly into Binary Ninja.

- [**WinDBG EXT MCP**](https://github.com/NadavLor/windbg-ext-mcp) – AI-assisted kernel debugging with WinDbg. Real-time analysis of crash dumps.

- [**mcp-windbg**](https://github.com/svnscha/mcp-windbg) – AI-powered interactive debugger integration for WinDbg/CDB to analyze crash dumps and control execution.

- [**Jadx MCP Plugin**](https://github.com/mobilehackinglab/jadx-mcp-plugin) – Exposes Jadx decompiler features for **Android Pentesting**.

- [**Sentry MCP**](https://github.com/getsentry/sentry-mcp) – Analyze error logs and stack traces to identify crash points or logic bugs.

- [**Greptile MCP**](https://github.com/greptileai/greptile-vscode) – Semantic code search to find vulnerable logic in large codebases.

- [**Semgrep MCP**](https://github.com/semgrep/semgrep) – **(Official)** Built directly into the Semgrep binary (`semgrep mcp`). Run static analysis scans, analyze code vulnerabilities, and draft custom rules.

- [**Slither MCP**](https://github.com/trailofbits/slither-mcp) – **(Web3)** Static analysis for Solidity smart contracts using Trail of Bits' Slither.

- [**Aderyn**](https://github.com/Cyfrin/aderyn) – Fast static analysis for Solidity smart contracts.

- [**mcp-gdb**](https://github.com/signal-slot/mcp-gdb) – GDB server integration for debugging applications.

- [**lldb-mcp**](https://github.com/stass/lldb-mcp) – LLDB debugger integration for controlling debug sessions via MCP.

- [**radare2-mcp**](https://github.com/radareorg/radare2-mcp) – Deep integration with Radare2 (r2) for reverse engineering.

- [**codeql-mcp**](https://github.com/JordyZomer/codeql-mcp) – Run CodeQL queries using natural language for variant analysis.

- [**pwno-mcp**](https://github.com/pwno-io/pwno-mcp) – Advanced GDB/pwndbg integration tailored for exploitation and LLM usage.

- [**frida-mcp**](https://github.com/dnakov/frida-mcp) – Dynamic instrumentation and hooking using Frida.

- [**embedded-debugger-mcp**](https://github.com/Adancurusul/embedded-debugger-mcp) – Debug embedded systems (ARM, RISC-V) via probe-rs.

- [**mcp-android-server-python**](https://github.com/nim444/mcp-android-server-python) – Android automation and UI inspection via uiautomator2.

- [**mobile-mcp**](https://github.com/mobile-next/mobile-mcp) – Cross-platform mobile automation (iOS/Android) for emulators and real devices.

- [**MobSF MCP**](https://github.com/pullkitsan/mobsf-mcp-server) – Scan and analyze APK/IPA files using Mobile Security Framework (MobSF).

- [**Volatility MCP**](https://github.com/bornpresident/Volatility-MCP-Server) – Integrate Volatility 3 for automated memory forensics.

- [**MCP Security Tools**](https://github.com/Ta0ing/MCP-SecurityTools) – Collection including Uncover (FOFA/Shodan), Enscan, and more.


---



<div id="web"></div>

## 🌐 Web, Network & Protocol

*Tools for dynamic assessment, traffic interception, API security, and database interaction.*



- [**Burp Suite MCP**](https://github.com/PortSwigger/mcp-server) – The industry standard for web security testing, now controllable via AI.

- [**Nuclei MCP**](https://github.com/addcontent/nuclei-mcp) – Orchestrate fast vulnerability scanning with Nuclei templates.

- [**Nikto MCP**](https://github.com/weldpua2008/nikto-mcp) – Command-line wrapper to run Nikto web server scans for vulnerability identification.

- [**Chrome DevTools MCP**](https://github.com/ChromeDevTools/chrome-devtools-mcp) – **(Official)** Control and inspect Google Chrome via Chrome DevTools Protocol. Perform DOM inspection, script evaluation, and network analysis.

- [**Playwright MCP**](https://github.com/microsoft/playwright-mcp) – Browser automation for dynamic testing, scraping, or bypassing client-side controls.

- [**Puppeteer MCP**](https://github.com/merajmehrabi/puppeteer-mcp-server) – Headless Chrome automation for XSS verification and admin bot simulation.

- [**PostgreSQL MCP**](https://github.com/crystaldba/postgres-mcp) – Connect to Postgres DBs to inspect schemas and test SQL queries.

- [**MySQL MCP**](https://github.com/benborla/mcp-server-mysql) – MySQL/MariaDB interaction for database assessment.

- [**Redis MCP**](https://github.com/redis/mcp-redis) – **(Official)** Interact with Redis databases. Common target for RCE and data exfiltration.

- [**MongoDB MCP**](https://github.com/mongodb-js/mongodb-mcp-server) – **(Official)** Inspect MongoDB collections and test for NoSQL injection.

- [**SQLite MCP**](https://github.com/jparkerweb/mcp-sqlite) – Analyze local SQLite database files (Essential for **Mobile/Browser Forensics**).

- [**AKTO MCP Server**](https://www.akto.io/mcp) – Automate API discovery and security testing (Broken Object Level Authorization, etc.).

- [**Cloudflare MCP Server**](https://github.com/cloudflare/mcp-server-cloudflare) – Manage WAF rules, review logs, and secure edge configurations.

- [**Illumio MCP**](https://github.com/alexgoller/illumio-mcp-server) – Zero Trust segmentation and traffic flow analysis.

- [**Fetch MCP**](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch) – Simple HTTP client for manual fuzzing or crafting raw requests.

- [**mcp-server-fuzzer**](https://github.com/Agent-Hellboy/mcp-server-fuzzer) – A generic fuzzer for testing and stressing other MCP servers.

- [**mcpcap**](https://github.com/mcpcap/mcpcap) – Network traffic analysis (PCAP) and packet inspection.

- [**WireMCP**](https://github.com/0xKoda/WireMCP) – Real-time network analysis using Wireshark (tshark).



---



<div id="weapon"></div>

## ⚔️ Weaponization & Exploitation

*Tools for payload generation, system exploitation, and command execution.*



> **Note:** Many tools in "Infrastructure" (like CLI access) can be used for exploitation.



- [**Command Line MCP**](https://github.com/g0t4/mcp-server-commands) – **⚠️ Dangerous.** Allows AI to execute arbitrary shell commands. Powerful for specialized exploitation chains but requires strict sandboxing.

- [**MetasploitMCP**](https://github.com/GH05TCREW/MetasploitMCP) – Control the Metasploit Framework for vulnerability scanning and exploitation.

- [**HexStrike AI**](https://github.com/0x4m4/hexstrike-ai) – Automated offensive security suite running 150+ tools.

- [**MCP Security Hub**](https://github.com/FuzzingLabs/mcp-security-hub) – A production-ready, Dockerized collection of 36+ MCP servers bridging 185+ offensive security tools (Nmap, Ghidra, Nuclei, SQLMap, Hashcat, etc.) into AI agents.

- [**MasterMCP**](https://github.com/slowmist/MasterMCP) – **(Research)** Demonstration toolkit allowing cross-MCP attacks (use with caution).

- [**Damn Vulnerable MCP Server**](https://github.com/harishsg993010/damn-vulnerable-MCP-server) – **(Educational)** Deliberately vulnerable MCP server for CTF and security training.

- [**MCP Injection Experiments**](https://github.com/invariantlabs-ai/mcp-injection-experiments) – **(Research)** Code snippets and proofs-of-concept for MCP tool poisoning attacks.

- [**Offensive MCP AI**](https://github.com/CyberSecurityUP/Offensive-MCP-AI) – Suite of offensive security tools for AI agents.



---



<div id="crypto"></div>

## 🔓 Cryptography & Cracking

*Tools for hash cracking, decoding, and cryptographic operations.*



- [**Hashcat MCP**](https://github.com/MorDavid/hashcat-mcp) – Orchestrate Hashcat for password cracking using natural language.



---



<div id="postexp"></div>

## 🏴 Post-Exploitation & Active Directory

*Tools for internal reconnaissance, privilege escalation, and lateral movement.*



- [**BloodHound MCP AI**](https://github.com/MorDavid/BloodHound-MCP-AI) – Analyze Active Directory attack paths using graph queries via AI.

- [**RoadRecon MCP**](https://github.com/atomicchonk/roadrecon_mcp_server) – Azure Active Directory (Entra ID) enumeration and analysis.



---



<div id="infra"></div>

## 🏗️ Infrastructure, Utils & Orchestration

*Cloud security, container management, forensics, and agentic frameworks.*



### ☁️ Cloud & Container Security

- [**Terraform MCP**](https://github.com/hashicorp/terraform-mcp-server) – **(Official)** Analyze Terraform IaC for cloud misconfigurations or hardcoded secrets.

- [**Trivy MCP**](https://github.com/aquasecurity/trivy-mcp) – **(Official)** Aqua Security's official Trivy plugin. Perform container, filesystem, and repository vulnerability scans using natural language.

- [**Snowflake MCP**](https://github.com/Snowflake-Labs/mcp) – **(Official)** Interact with Snowflake Data Cloud (Data exfiltration simulation / Access Audit).

- [**Kubernetes MCP**](https://github.com/Flux159/mcp-server-kubernetes) – Enumerate and manage K8s clusters (Pod security, RBAC checks).

- [**AWS MCP**](https://awslabs.github.io/mcp/) – Inspect AWS resources (S3 buckets, IAM roles, EC2) for misconfigurations.

- [**Docker MCP**](https://hub.docker.com/u/mcp) – Manage Docker containers and images. Useful for setting up attack labs or analyzing container images.

- [**Auth0 MCP**](https://github.com/auth0/auth0-mcp-server) – **(Official)** Management and interaction with Auth0 identity platform.




### ⚙️ Infrastructure Analysis (Monitoring)

- [**Grafana MCP**](https://github.com/grafana/mcp-grafana) – **(Official)** Access dashboards and data sources to visualize internal network status.

- [**Prometheus MCP**](https://github.com/pab1it0/prometheus-mcp-server) – Query monitoring metrics to uncover internal system loads and running services.



### 🛠️ System & Forensics

- [**Filesystem MCP**](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) – Read/write local files. Critical for **Log Analysis**, config auditing, and data exfiltration simulation.

- [**Git MCP**](https://github.com/modelcontextprotocol/servers/tree/main/src/git) – Analyze git history and diffs to find sensitive data or past vulnerabilities.

- [**MCP Timeserver**](https://github.com/SecretiveShell/MCP-timeserver) – Provides precise time context for correlation rules.

- [**pty-mcp-server**](https://github.com/phoityne/pty-mcp-server) – Spawn and interact with pseudo-terminals (PTY) for shell access.



### 🛡️ Security Operations (Blue/Purple)

- [**Google Security Operations MCP**](https://github.com/google/mcp-security) – Chronicle & Mandiant integration for threat hunting.

- [**Elastic Security MCP**](https://github.com/elastic/mcp-server-elasticsearch) – SIEM interaction for log search and anomaly detection.

- [**Check Point Quantum MCP**](https://github.com/CheckPointSW/mcp-servers) – Firewall management and policy review.

- [**Heimdall**](https://github.com/shinzo-labs/heimdall) – Access control and governance layer for MCP tools.

- [**ToolHive**](https://github.com/stacklok/toolhive) – Management and registry for secure MCP server deployment.

- [**MCP Scan**](https://github.com/invariantlabs-ai/mcp-scan) – Scan MCP connections for vulnerabilities and log interactions.

- [**MCP Shield**](https://github.com/riseandignite/mcp-shield) – Security scanner specifically designed for MCP servers.

- [**MCP Guardian**](https://github.com/eqtylab/mcp-guardian) – Proxy and secure your MCP servers with access control.



### 🤝 Ops & Communication

- [**Discord MCP**](https://github.com/hanweg/mcp-discord) – Control Discord (can be used for C2 simulation or notifications).

- [**Telegram MCP**](https://github.com/qpd-v/mcp-communicator-telegram) – Telegram integration.

- [**WhatsApp MCP**](https://github.com/lharries/whatsapp-mcp) – WhatsApp Web API integration.

- [**Notion MCP**](https://developers.notion.com/docs/mcp) – Automated pentest reporting to Notion.

- [**Obsidian MCP**](https://github.com/calclavia/mcp-obsidian) – Manage local knowledge base (Obsidian) for engagement notes.

- [**GitLab MCP**](https://github.com/mcp-parliament/gitlab-mcp-server) – Manage repositories and issues.



### 🤖 Agentic AI Frameworks

*Frameworks to build, test, and orchestrate your own offensive agents.*



- [**Microsoft AutoGen**](https://github.com/microsoft/autogen)

- [**CrewAI**](https://github.com/crewAIInc/crewAI)

- [**LangChain**](https://github.com/langchain-ai/langchain)

- [**LangGraph**](https://github.com/langchain-ai/langgraph)

- [**Microsoft Semantic Kernel**](https://github.com/microsoft/semantic-kernel)

- [**Agno**](https://github.com/agno-agi/agno)

- [**CAI (Cybersecurity AI)**](https://github.com/aliasrobotics/CAI)

- [**AgentFence**](https://github.com/agentfence/agentfence) – Testing AI agent vulnerabilities.

- [**Pentagi**](https://github.com/vxcontrol/pentagi) – Autonomous AI penetration tester.

- [**Agentic Security Scanner**](https://github.com/msoedov/agentic_security)



---



## 🤝 Contributing



Contributions are always welcome!



1.  Fork the project.

2.  Create your feature branch (`git checkout -b add/new-mcp-tool`).

3.  Add the link and description to the appropriate category.

4.  Commit your changes.

5.  Open a Pull Request.



**Important:** Please ensure your submission meets one of the following criteria:

* **30+ GitHub Stars**

* **Personally Tested:** If it has fewer stars, please explain in the PR how you used it and why it's useful.



---



## 🧾 License



[![CC0](https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](https://creativecommons.org/publicdomain/zero/1.0)  

This project is released under the **Creative Commons Zero** license. Public domain — use freely.
