# Awesome Offensive Security MCP Servers [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> **Supercharge your security tools with AI!** > This is a curated list of **Model Context Protocol (MCP)** servers specifically designed for **Red Teaming, Pentesting, Vulnerability Research, and Security Operations**.  
> Built for security professionals who want to unleash the full potential of Agentic AI in their security stack.

---

## ⚠️ Disclaimer & Criteria

* **Criteria:** This list is curated based on a subjective selection of tools that generally have **30+ GitHub Stars**, are **Official** implementations, or demonstrate significant utility in offensive security workflows.
* **Responsibility:** The use of the tools and servers listed in this repository is strictly for **educational and authorized testing purposes only**. The maintainers assume **no responsibility** for any misuse or damage caused by these tools. You are responsible for complying with all applicable laws and regulations.
* **Safety:** **Always audit the code** of MCP servers before connecting them to your environment, especially those capable of executing commands or reading files.

---

## 🚀 What is MCP?

**Model Context Protocol (MCP)** is an open standard that acts as a universal translator between AI models (like Claude, Gemini) and your local tools. It allows AI to safely query databases, execute scripts, and interact with APIs without hardcoded integrations.

For offensive security, this means your AI agent can now **run Nmap scans, analyze Ghidra decompilation, and query Shodan**—all within a single conversation context.

---

## 📑 Categories

- [🕵️ Reconnaissance & OSINT](#-reconnaissance--osint)
- [🔬 Vulnerability Research & Analysis](#-vulnerability-research--analysis)
- [🌐 Web, Network & Protocol](#-web-network--protocol)
- [⚔️ Weaponization & Exploitation](#-weaponization--exploitation)
- [🔓 Cryptography & Cracking](#-cryptography--cracking)
- [🏴 Post-Exploitation & Active Directory](#-post-exploitation--active-directory)
- [🏗️ Infrastructure, Utils & Orchestration](#-infrastructure-utils--orchestration)

---

## 🕵️ Reconnaissance & OSINT
*Tools for asset discovery, threat intelligence gathering, and external attack surface mapping.*

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

---

## 🔬 Vulnerability Research & Analysis
*Tools for static analysis, reverse engineering, mobile app analysis, and firmware inspection.*

- [**Ghidra MCP**](https://github.com/LaurieWired/GhidraMCP) – Deep integration with Ghidra for autonomous reverse engineering and function explanation.
- [**Ghidra MCP Alternative**](https://github.com/Bamimore-Tomi/ghidra_mcp) – Another variant of Ghidra MCP focusing on binary analysis capabilities.
- [**IDA Pro MCP**](https://github.com/mrexodia/ida-pro-mcp) – Control IDA Pro using LLMs for decompilation and analysis.
- [**Binary Ninja MCP**](https://github.com/MCPPhalanx/binaryninja-mcp) – Plugin to integrate AI workflows directly into Binary Ninja.
- [**WinDBG EXT MCP**](https://github.com/NadavLor/windbg-ext-mcp) – AI-assisted kernel debugging with WinDbg. Real-time analysis of crash dumps.
- [**Jadx MCP Plugin**](https://github.com/mobilehackinglab/jadx-mcp-plugin) – Exposes Jadx decompiler features for **Android Pentesting**.
- [**Sentry MCP**](https://github.com/modelcontextprotocol/servers/tree/main/src/sentry) – Analyze error logs and stack traces to identify crash points or logic bugs.

---

## 🌐 Web, Network & Protocol
*Tools for dynamic assessment, traffic interception, API security, and database interaction.*

- [**Burp Suite MCP**](https://github.com/PortSwigger/mcp-server) – The industry standard for web security testing, now controllable via AI.
- [**Nuclei MCP**](https://github.com/addcontent/nuclei-mcp) – Orchestrate fast vulnerability scanning with Nuclei templates.
- [**Playwright MCP**](https://github.com/microsoft/playwright-mcp) – Browser automation for dynamic testing, scraping, or bypassing client-side controls.
- [**PostgreSQL MCP**](https://github.com/modelcontextprotocol/servers/tree/main/src/postgres) – Connect to Postgres DBs to inspect schemas and test SQL queries.
- [**MySQL MCP**](https://github.com/designcombo/mcp-server-mysql) – MySQL/MariaDB interaction for database assessment.
- [**SQLite MCP**](https://github.com/modelcontextprotocol/servers/tree/main/src/sqlite) – Analyze local SQLite database files (Essential for **Mobile/Browser Forensics**).
- [**AKTO MCP Server**](https://www.akto.io/mcp) – Automate API discovery and security testing (Broken Object Level Authorization, etc.).
- [**Cloudflare MCP Server**](https://github.com/cloudflare/mcp-server-cloudflare) – Manage WAF rules, review logs, and secure edge configurations.
- [**Illumio MCP**](https://github.com/alexgoller/illumio-mcp-server) – Zero Trust segmentation and traffic flow analysis.

---

## ⚔️ Weaponization & Exploitation
*Tools for payload generation, system exploitation, and command execution.*

> **Note:** Many tools in "Infrastructure" (like CLI access) can be used for exploitation.

- [**Command Line MCP**](https://github.com/g0t4/mcp-server-commands) – **⚠️ Dangerous.** Allows AI to execute arbitrary shell commands. Powerful for specialized exploitation chains but requires strict sandboxing.
- *More coming soon... (e.g., Metasploit RPC wrappers, Canvas integration)*

---

## 🔓 Cryptography & Cracking
*Tools for hash cracking, decoding, and cryptographic operations.*

- [**Hashcat MCP**](https://github.com/MorDavid/hashcat-mcp) – Orchestrate Hashcat for password cracking using natural language.

---

## 🏴 Post-Exploitation & Active Directory
*Tools for internal reconnaissance, privilege escalation, and lateral movement.*

- [**BloodHound MCP AI**](https://github.com/MorDavid/BloodHound-MCP-AI) – Analyze Active Directory attack paths using Graph queries via AI.
- [**RoadRecon MCP**](https://github.com/atomicchonk/roadrecon_mcp_server) – Azure Active Directory (Entra ID) enumeration and analysis.

---

## 🏗️ Infrastructure, Utils & Orchestration
*Cloud security, container management, forensics, and agentic frameworks.*

### ☁️ Cloud & Container Security
- [**Kubernetes MCP**](https://github.com/Flux159/mcp-server-kubernetes) – Enumerate and manage K8s clusters (Pod security, RBAC checks).
- [**AWS MCP**](https://github.com/michaillat/mcp-aws) – Inspect AWS resources (S3 buckets, IAM roles, EC2) for misconfigurations.
- [**Docker MCP**](https://github.com/modelcontextprotocol/servers/tree/main/src/docker) – Manage Docker containers and images. Useful for setting up attack labs or analyzing container images.

### 🛠️ System & Forensics
- [**Filesystem MCP**](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) – Read/Write local files. Critical for **Log Analysis**, config auditing, and data exfiltration simulation.
- [**Git MCP**](https://github.com/modelcontextprotocol/servers/tree/main/src/git) – Analyze git history and diffs to find sensitive data or past vulnerabilities.
- [**MCP Timeserver**](https://github.com/SecretiveShell/MCP-timeserver) – Provides precise time context for correlation rules.

### 🛡️ Security Operations (Blue/Purple)
- [**Google Security Operations MCP**](https://github.com/google/mcp-security) – Chronicle & Mandiant integration for Threat Hunting.
- [**Elastic Security MCP**](https://github.com/elastic/mcp-server-elasticsearch) – SIEM interaction for log search and anomaly detection.
- [**Check Point Quantum MCP**](https://github.com/CheckPointSW/mcp-servers) – Firewall management and policy review.

### 🤝 Ops & Communication
- [**Discord MCP**](https://github.com/BurtTheCoder/mcp-discord) – Control Discord (Can be used for C2 simulation or notifications).
- [**Telegram MCP**](https://github.com/qpd-v/mcp-communicator-telegram) – Telegram integration.
- [**WhatsApp MCP**](https://github.com/lharries/whatsapp-mcp) – WhatsApp Web API integration.
- [**Notion MCP**](https://github.com/sgl-project/mcp-server-notion) – Automated pentest reporting to Notion.
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
- [**Pentagi**](https://github.com/vxcontrol/pentagi) – Autonomous AI Penetration Tester.
- [**Agentic Security Scanner**](https://github.com/msoedov/agentic_security)

---

## 🤝 Contributing

Contributions are welcome! If you know of an MCP server that fits the offensive security scope:

1.  Fork the project.
2.  Create your feature branch (`git checkout -b feature/AmazingMCP`).
3.  Add the link and description to the appropriate category.
4.  Commit your changes.
5.  Open a Pull Request.

**Note:** We particularly encourage contributions in the **Automotive Security** and **IoT/Hardware Hacking** domains!

---

## 🧾 License

[![CC0](https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](https://creativecommons.org/publicdomain/zero/1.0)  
This project is released under the **Creative Commons Zero** license. Public domain — use freely.
