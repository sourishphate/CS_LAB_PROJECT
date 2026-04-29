# Automated Penetration Testing Platform

A full-stack web application that replicates the workflow used by professional security teams. It chains together eight distinct phases — from initial reconnaissance through to final reporting — into a single orchestrated pipeline that a user can drive through a web dashboard.

## ⚠️ Ethical Warning

**This platform must only be used against systems for which explicit written authorisation has been obtained.** Unauthorised scanning and exploitation is illegal under the IT Act 2000 (India) and equivalent legislation worldwide.

- All scans require a defined scope — in-scope targets must be explicitly listed
- Rules of engagement must be agreed before any scan begins
- Production systems must never be targeted — use dedicated lab VMs or CTF environments
- All scan activity is logged in the audit database for accountability

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Technology Stack](#technology-stack)
4. [Project Structure](#project-structure)
5. [Database Schema](#database-schema)
6. [API Reference](#api-reference)
7. [Scan Phases](#scan-phases)
8. [Frontend Components](#frontend-components)
9. [Installation & Setup](#installation--setup)
10. [Usage Guide](#usage-guide)
11. [Computer Science Concepts](#computer-science-concepts)
12. [Security Considerations](#security-considerations)
13. [Future Enhancements](#future-enhancements)

---

## Project Overview

This platform is designed to demonstrate applied computer science concepts across networking, cryptography, data structures, operating systems, and databases, while producing real security value against lab targets. It serves as:

- A strong baseline scanner for security assessments
- An academic demonstration of how security tooling is architected
- A practical application of cybersecurity lab concepts

### Project Goals

The primary academic goals of this project are:

- Apply networking concepts (TCP/IP, DNS, HTTP, TLS) in a practical security context
- Implement cryptographic analysis using skills from the OpenSSL lab
- Demonstrate data structures (heaps, graphs) solving real-world prioritisation problems
- Build a multi-phase pipeline with orchestration, scheduling, and state management
- Produce professional security reports with risk scoring aligned to NIST/CIS frameworks

---

## Features

### Dashboard Features

| Feature | Description |
|---------|-------------|
| **Target Input** | Domain or IP address entry for scan targets |
| **Scope Selector** | Choose between Full, DNS-only, OSINT-only, or Network-only scans |
| **Module Toggles** | Enable/disable individual recon modules as pill toggles |
| **Rate Limiter** | Slider controlling requests per second to avoid IDS detection |
| **Live Progress Bar** | Real-time scan status with phase pills (done/running/pending) |
| **Stats Cards** | Live updating stats for subdomains, IPs, emails, ports, vulnerabilities |

### Results Features

| Feature | Description |
|---------|-------------|
| **DNS Records Table** | Clean display of all record types (A, MX, NS, TXT, CNAME) |
| **WHOIS Panel** | Registrar, dates, name servers, registrant country |
| **Subdomains List** | Scrollable table with live/dead status |
| **SSL/TLS Report** | Per-host cert status with colour-coded risk rating |
| **Service Fingerprinting** | Port, service, version, CVE flags per host |
| **Vulnerability Queue** | Sorted by CVSS score, highest risk at top |
| **Attack Surface Graph** | Visual node-edge visualisation of discovered assets |

### Export & History

| Feature | Description |
|---------|-------------|
| **PDF Export** | Executive summary with risk scoring (planned) |
| **JSON Export** | Full technical findings for developer/analyst use |
| **Scan History** | List of past runs with date, target, findings count |
| **Diff View** | Side-by-side comparison of two scans showing changes |

### AI-Powered Analytics

| Feature | Description |
|---------|-------------|
| **Vulnerability Summary** | AI-generated risk assessment and prioritization of discovered vulnerabilities |
| **Security Recommendations** | Actionable security improvement suggestions based on findings |
| **Attack Vectors** | Analysis of potential attack paths and exploitation scenarios |
| **Executive Summary** | High-level overview for management and stakeholders |
| **Remediation Plan** | Step-by-step guidance to fix identified vulnerabilities |

---

## Technology Stack

### Core Technologies

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Backend** | Python 3.11+ (via Next.js API routes) | Core logic for all scan modules |
| **API Layer** | Next.js 16 API Routes | REST endpoints connecting frontend to backend |
| **Frontend** | React 19 + TypeScript | Web dashboard and result visualisation |
| **Styling** | Tailwind CSS 4 + shadcn/ui | Component library and styling |
| **Database** | SQLite + Prisma ORM | Scan history, CVE cache, findings store |
| **State Management** | React State + useEffect | Client state management |

### Additional Libraries

| Library | Purpose |
|---------|---------|
| `lucide-react` | Icon library |
| `recharts` | Chart visualisation |
| `sonner` | Toast notifications |
| `zod` | Schema validation |
| `date-fns` | Date formatting |
| `z-ai-web-dev-sdk` | AI/LLM integration for analytics |
| `react-markdown` | Markdown rendering for AI responses |

---

## Project Structure

```
/home/z/my-project/
├── prisma/
│   └── schema.prisma              # Database schema definition
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── scans/
│   │   │   │   ├── route.ts       # GET/POST /api/scans
│   │   │   │   └── [id]/
│   │   │   │       ├── route.ts           # GET/DELETE /api/scans/[id]
│   │   │   │       ├── start/route.ts     # POST /api/scans/[id]/start
│   │   │   │       ├── results/route.ts   # GET /api/scans/[id]/results
│   │   │   │       └── report/route.ts    # GET /api/scans/[id]/report
│   │   │   ├── analyze/
│   │   │   │   └── route.ts       # POST /api/analyze (LLM analytics)
│   │   │   └── route.ts           # Health check endpoint
│   │   ├── globals.css            # Global styles
│   │   ├── layout.tsx             # Root layout
│   │   └── page.tsx               # Main dashboard page
│   ├── components/
│   │   ├── ui/                    # shadcn/ui components
│   │   └── ai-analytics.tsx       # AI Analytics component
│   ├── hooks/
│   │   ├── use-toast.ts           # Toast hook
│   │   └── use-mobile.ts          # Mobile detection hook
│   ├── lib/
│   │   ├── db.ts                  # Prisma client
│   │   ├── utils.ts               # Utility functions
│   │   └── services/
│   │       └── scan-service.ts    # Core scan orchestration
│   └── types/
│       └── pentest.ts             # TypeScript type definitions
├── public/                        # Static assets
├── db/                            # SQLite database files
├── package.json                   # Dependencies
├── tailwind.config.ts             # Tailwind configuration
├── tsconfig.json                  # TypeScript configuration
└── README.md                      # This file
```

---

## Database Schema

### Entity Relationship Diagram

```
┌─────────────┐       ┌─────────────────┐
│    Scan     │──1:1──│   ReconResult   │
└─────────────┘       └─────────────────┘
       │
       │ 1:N
       ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│  ServiceResult  │   │    SSLResult    │   │ Vulnerability   │
└─────────────────┘   └─────────────────┘   └─────────────────┘
       │
       │ 1:N
       ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ AttackSurface   │   │     Report      │   │    AuditLog     │
└─────────────────┘   └─────────────────┘   └─────────────────┘
```

### Table Definitions

#### `scans` - Main scan management
| Column | Type | Description |
|--------|------|-------------|
| `id` | String (CUID) | Primary key |
| `target` | String | Domain or IP address |
| `status` | String | pending, running, completed, failed, paused |
| `progress` | Int | 0-100 percentage |
| `currentPhase` | String? | Current phase being executed |
| `scope` | String | full, dns, osint, network |
| `rateLimit` | Int | Requests per second |
| `createdAt` | DateTime | Creation timestamp |
| `startedAt` | DateTime? | Scan start timestamp |
| `completedAt` | DateTime? | Scan completion timestamp |

#### `recon_results` - Reconnaissance findings
| Column | Type | Description |
|--------|------|-------------|
| `id` | String | Primary key |
| `scanId` | String | Foreign key to scans |
| `whoisData` | String? | JSON - WHOIS information |
| `dnsRecords` | String? | JSON - DNS records |
| `subdomains` | String? | JSON - Discovered subdomains |
| `emails` | String? | JSON - Harvested emails |
| `names` | String? | JSON - Discovered names |
| `asnData` | String? | JSON - ASN information |
| `liveIPs` | String? | JSON - Live IP addresses |

#### `service_results` - Service fingerprinting
| Column | Type | Description |
|--------|------|-------------|
| `id` | String | Primary key |
| `scanId` | String | Foreign key to scans |
| `ip` | String | IP address |
| `port` | Int | Port number |
| `protocol` | String | tcp/udp |
| `service` | String | Service name (http, ssh, etc.) |
| `version` | String? | Software version |
| `banner` | String? | Raw banner |
| `os` | String? | Detected OS |
| `cveFlags` | String? | JSON - Associated CVEs |

#### `ssl_results` - SSL/TLS analysis
| Column | Type | Description |
|--------|------|-------------|
| `id` | String | Primary key |
| `scanId` | String | Foreign key to scans |
| `host` | String | Hostname/IP |
| `port` | Int | Port number |
| `issuer` | String? | Certificate issuer |
| `subject` | String? | Certificate subject |
| `daysRemaining` | Int? | Days until expiry |
| `isExpired` | Boolean | Certificate expired |
| `isSelfSigned` | Boolean | Self-signed certificate |
| `protocol` | String? | TLS version |
| `cipherSuite` | String? | Cipher suite |
| `riskRating` | String | green, yellow, red |

#### `vulnerability_results` - Vulnerability findings
| Column | Type | Description |
|--------|------|-------------|
| `id` | String | Primary key |
| `scanId` | String | Foreign key to scans |
| `cveId` | String | CVE identifier |
| `title` | String? | Vulnerability title |
| `description` | String? | Detailed description |
| `host` | String | Affected host |
| `port` | Int? | Affected port |
| `cvssScore` | Float | CVSS score (0-10) |
| `severity` | String | critical, high, medium, low, info |
| `exploitAvailable` | Boolean | Exploit exists |
| `status` | String | open, verified, false-positive, fixed |

#### `reports` - Generated reports
| Column | Type | Description |
|--------|------|-------------|
| `id` | String | Primary key |
| `scanId` | String | Foreign key to scans |
| `totalHosts` | Int | Number of hosts |
| `totalPorts` | Int | Number of open ports |
| `totalVulns` | Int | Total vulnerabilities |
| `criticalVulns` | Int | Critical severity count |
| `highVulns` | Int | High severity count |
| `riskScore` | Int | Overall risk score (0-100) |
| `complianceData` | String? | JSON - NIST/CIS mappings |

#### `cve_cache` - Local CVE database
| Column | Type | Description |
|--------|------|-------------|
| `id` | String | Primary key |
| `cveId` | String | Unique CVE identifier |
| `title` | String? | Vulnerability title |
| `description` | String? | Detailed description |
| `cvssScore` | Float? | CVSS score |
| `severity` | String? | Severity level |
| `exploitAvailable` | Boolean | Known exploit exists |

---

## API Reference

### Base URL

All API endpoints are relative to the application base URL.

### Endpoints

#### `GET /api/scans`

Retrieve all scans, ordered by creation date (newest first).

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "clx123abc",
      "target": "example.com",
      "status": "completed",
      "progress": 100,
      "currentPhase": "completed",
      "scope": "full",
      "rateLimit": 10,
      "createdAt": "2024-01-15T10:30:00.000Z",
      "completedAt": "2024-01-15T10:35:00.000Z"
    }
  ]
}
```

---

#### `POST /api/scans`

Create a new scan.

**Request Body:**
```json
{
  "target": "example.com",
  "scope": "full",
  "rateLimit": 10,
  "modules": {
    "whoisEnabled": true,
    "dnsEnabled": true,
    "subdomainEnabled": true,
    "osintEnabled": true,
    "shodanEnabled": false,
    "asnEnabled": true,
    "sslEnabled": true,
    "vulnEnabled": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scanId": "clx123abc",
    "message": "Scan created successfully"
  }
}
```

---

#### `GET /api/scans/[id]`

Retrieve a single scan with all related data.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "clx123abc",
    "target": "example.com",
    "status": "completed",
    "reconResults": { ... },
    "serviceResults": [ ... ],
    "sslResults": [ ... ],
    "vulnResults": [ ... ],
    "report": { ... }
  }
}
```

---

#### `DELETE /api/scans/[id]`

Delete a scan and all associated results.

**Response:**
```json
{
  "success": true,
  "message": "Scan deleted"
}
```

---

#### `POST /api/scans/[id]/start`

Start executing a scan.

**Request Body:**
```json
{
  "modules": {
    "whoisEnabled": true,
    "dnsEnabled": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Scan started"
}
```

---

#### `GET /api/scans/[id]/results`

Get complete scan results with attack surface graph.

**Response:**
```json
{
  "success": true,
  "data": {
    "scan": { ... },
    "recon": { ... },
    "services": [ ... ],
    "ssl": [ ... ],
    "vulnerabilities": [ ... ],
    "attackSurface": {
      "nodes": [ ... ],
      "edges": [ ... ]
    },
    "stats": {
      "subdomainsFound": 8,
      "liveIPs": 6,
      "emailsFound": 4,
      "openPorts": 15,
      "vulnsFound": 3,
      "criticalVulns": 1
    }
  }
}
```

---

#### `GET /api/scans/[id]/report?format=json`

Export scan report.

**Query Parameters:**
- `format` - Report format (`json` supported, `pdf` planned)

**Response:**
JSON file download with full technical findings.

---

#### `POST /api/analyze`

Run AI-powered analysis on scan results.

**Request Body:**
```json
{
  "scanId": "clx123abc",
  "analysisType": "vulnerability_summary"
}
```

**Analysis Types:**
| Type | Description |
|------|-------------|
| `vulnerability_summary` | Risk assessment and prioritization |
| `security_recommendations` | Actionable security improvements |
| `attack_vectors` | Potential attack paths and scenarios |
| `executive_summary` | Management-level overview |
| `remediation_plan` | Step-by-step fix guidance |

**Response:**
```json
{
  "success": true,
  "data": {
    "analysisType": "vulnerability_summary",
    "result": "## Vulnerability Analysis\n\n...",
    "generatedAt": "2024-01-15T10:30:00.000Z"
  }
}
```

---

## Scan Phases

### Phase 1: Reconnaissance

The first and most data-intensive phase. Collects all publicly available information about the target before any active scanning begins.

#### Sub-modules

| Module | Description | Tools/Libraries |
|--------|-------------|-----------------|
| **WHOIS Lookup** | Registrar, creation date, name servers, registrant country | python-whois |
| **DNS Enumeration** | A, MX, NS, TXT, CNAME records | dnspython |
| **Subdomain Enumeration** | Passive discovery via wordlist | sublist3r |
| **OSINT/Email Harvesting** | Google, Bing, LinkedIn queries for exposed emails | theHarvester |
| **Shodan Integration** | Open ports, software banners, known CVEs | shodan |
| **Network Range/ASN Discovery** | Map IPs to organisation and CIDR block | ipwhois |

#### Output

All sub-module outputs are merged into a single `target_profile.json` containing:
- Deduplicated IP addresses
- Discovered subdomains
- Harvested emails
- ASN data
- Shodan findings

---

### Phase 2: Service Fingerprinting

Runs against every live IP discovered in recon. Grabs service banners and maps them against known vulnerable versions.

#### Detection Types

| Service | Detection Method |
|---------|-----------------|
| **Operating System** | TTL values and TCP/IP stack behaviour |
| **HTTP Servers** | Apache, Nginx, IIS version from Server header |
| **SSH** | Version string from banner |
| **FTP/SMTP/IMAP** | Protocol banners |
| **Custom Ports** | Raw socket connection with response parsing |

#### CS Concept

This module applies socket programming at a low level:
- Raw TCP connections
- Byte-level response parsing
- Regex pattern matching against version signature database
- Direct application of OSI model layers 4 and 7

---

### Phase 3: SSL/TLS Certificate Analysis

Analyses the TLS configuration of every HTTPS-capable host discovered.

#### Checks Performed

| Check | Description |
|-------|-------------|
| **Certificate Expiry** | Days remaining; alerts if under 30 days |
| **Self-signed Detection** | Checks if issuer matches subject |
| **Subject CN Mismatch** | Certificate does not match domain |
| **Weak Cipher Suites** | Flags RC4, DES, MD5, SHA-1, export-grade ciphers |
| **Protocol Version** | Flags SSLv2, SSLv3, TLS 1.0 as insecure |
| **Chain Validation** | Incomplete or untrusted chains |
| **Public Key Strength** | RSA < 2048 bit or EC < 256 bit flagged |

#### Risk Ratings

| Rating | Condition |
|--------|-----------|
| **Green** | No issues detected |
| **Yellow** | Weak protocols/ciphers |
| **Red** | Expired or self-signed certificates |

---

### Phase 4: Vulnerability Scanning

Matches discovered services against known CVEs and calculates risk scores.

#### Process

1. **Service-to-CVE Mapping** - Match service versions against CVE database
2. **Severity Aggregation** - Calculate CVSS scores for each finding
3. **Deduplication** - Remove duplicate CVEs across hosts
4. **Priority Queue** - Sort using max-heap (heapq) for highest risk first

#### Severity Levels

| Level | CVSS Range | Colour |
|-------|------------|--------|
| Critical | 9.0 - 10.0 | Red |
| High | 7.0 - 8.9 | Orange |
| Medium | 4.0 - 6.9 | Yellow |
| Low | 0.1 - 3.9 | Blue |
| Info | 0.0 | Gray |

---

### Phase 5: Exploitation Engine

CVE-to-exploit matching with safe exploit mode and production safeguards.

#### Features

- CVE-to-exploit database lookup
- Safe mode (PoC capture only)
- Production safeguards to prevent unintended damage
- Exploit success rate tracking

---

### Phase 6: Post-Exploitation

Lateral movement detection and privilege escalation analysis.

#### Capabilities

- Lateral movement possibility detection
- Privilege escalation vector identification
- Credential harvesting potential
- Persistence mechanism discovery

---

### Phase 7: Reporting

Generate professional security reports with risk scoring.

#### Report Types

| Type | Format | Purpose |
|------|--------|---------|
| **Executive Summary** | PDF | Management overview with risk scoring |
| **Technical Report** | JSON | Full findings for developers/analysts |
| **Compliance Mapping** | JSON | NIST/CIS framework alignment |

#### Risk Score Calculation

```
Risk Score = min(100, 
  (Critical Vulns × 25) + 
  (Total Vulns × 5) + 
  (Open Ports > 20 ? 10 : 0)
)
```

---

### Phase 8: Orchestration & Dashboard

Phase chaining, workflow logic, parallel scans, scheduling, and live progress UI.

#### Features

- **Phase Chaining** - Sequential execution with data handoff
- **If-Then Logic** - Conditional phase execution based on findings
- **Parallel Scans** - Multiple targets simultaneously (planned)
- **Scheduling** - Cron-based scan scheduling (planned)
- **Live Progress** - Real-time UI updates via polling

---

## Frontend Components

### Main Dashboard (`src/app/page.tsx`)

A comprehensive single-page application with four main tabs:

#### Tab 1: Dashboard

```
┌─────────────────────────────────────────────────────────────┐
│  New Scan                                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Target: [example.com          ] [Start Scan]        │   │
│  └─────────────────────────────────────────────────────┘   │
│  Scope: [FULL] [DNS] [OSINT] [NETWORK]                     │
│  Rate Limit: ──────●────────────────── 10 req/sec          │
│  Modules:                                                   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │ WHOIS    [✓] │ │ DNS      [✓] │ │ Subdomain[✓] │        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Current Scan Progress                                      │
│  example.com                                    [completed] │
│  ████████████████████████████████████████████ 100%         │
│  ✓ Reconnaissance  ✓ Fingerprinting  ✓ SSL Analysis        │
│  ✓ Vuln Scanning   ✓ Exploitation    ✓ Reporting           │
└─────────────────────────────────────────────────────────────┘

Stats Cards:
┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
│    8    │ │    6    │ │    4    │ │   15    │ │    3    │ │    1    │
│Subdomain│ │ Live IPs│ │ Emails  │ │  Ports  │ │  Vulns  │ │ Critical│
└─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘
```

#### Tab 2: Results

Organized results panels:
- **Subdomains Table** - Name, IP, Status
- **DNS Records** - Type, Name, Value
- **WHOIS Panel** - Registrar, dates, nameservers
- **Services Table** - IP, Port, Service, Version, CVEs
- **SSL Report** - Host, Protocol, Risk Rating
- **Vulnerability Queue** - CVE, CVSS, Severity (sorted)
- **Attack Surface Graph** - Visual node-edge diagram

#### Tab 3: History

Scan history table with actions:
- View results
- Export report
- Delete scan
- Compare scans (diff view)

#### Tab 4: Tools

Utility tools:
- CVE Lookup
- Hash Cracker (MD5, SHA1, SHA256)
- Packet Capture (placeholder)
- Scan Diff

---

## Installation & Setup

### Prerequisites

- **Node.js 18+** (Download from [nodejs.org](https://nodejs.org/))
- **npm** (Comes with Node.js) or **yarn**
- **Git** (Download from [git-scm.com](https://git-scm.com/))
- SQLite3 (Included with Prisma)

### Quick Start (Windows)

```powershell
# Clone the repository
git clone <repository-url>
cd pentest-platform

# Install dependencies
npm install

# Set up database
npm run db:push

# Start development server
npm run dev
```

### Quick Start (Linux/macOS)

```bash
# Clone the repository
git clone <repository-url>
cd pentest-platform

# Install dependencies
npm install

# Set up database
npm run db:push

# Start development server
npm run dev
```

### Environment Variables

Create a `.env` file in the root directory:

```env
DATABASE_URL="file:./db/custom.db"
```

**Windows users**: You can also use:
```env
DATABASE_URL="file:./db/custom.db"
```

### Database Commands

```bash
# Push schema changes to database
npm run db:push

# Generate Prisma client
npm run db:generate

# Create a migration
npm run db:migrate

# Reset database (WARNING: deletes all data)
npm run db:reset

# Open Prisma Studio (GUI database viewer)
npm run db:studio
```

### Development Commands

```bash
# Start development server (runs on http://localhost:3000)
npm run dev

# Run linter
npm run lint

# Build for production
npm run build

# Start production server
npm run start
```

### Windows-Specific Notes

1. **PowerShell Execution Policy**: If you get an error about running scripts, run:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

2. **Using Command Prompt vs PowerShell**: All npm commands work in both. PowerShell is recommended.

3. **Port 3000 in use**: If port 3000 is already in use, you can change it:
   ```powershell
   # Use a different port
   npx next dev -p 3001
   ```

4. **Database location**: The SQLite database will be created at `db/custom.db` relative to the project root.

5. **Opening Prisma Studio**:
   ```powershell
   npm run db:studio
   ```
   This opens a web-based GUI to view and edit your database.

### Troubleshooting

#### "Error code 14: Unable to open the database file"

This error occurs when SQLite cannot find or create the database file. Fix it by:

1. **Create the db folder manually**:
   ```powershell
   # In PowerShell, from the project root
   mkdir db
   ```

2. **Verify your .env file** contains:
   ```env
   DATABASE_URL="file:./db/custom.db"
   ```

3. **Re-run database setup**:
   ```powershell
   npm run db:push
   ```

4. **Restart the development server**:
   ```powershell
   # Press Ctrl+C to stop the server, then:
   npm run dev
   ```

#### "Prisma Client not initialized"

Run this command to regenerate the Prisma client:
```powershell
npm run db:generate
```

---

## Usage Guide

### Starting a New Scan

1. Navigate to the **Dashboard** tab
2. Enter a target domain or IP address in the target field
3. Select a scan scope:
   - **Full** - All reconnaissance modules
   - **DNS** - DNS records only
   - **OSINT** - Email and name harvesting
   - **Network** - Network range discovery
4. Adjust the rate limiter (lower values avoid IDS detection)
5. Enable/disable individual modules using toggles
6. Click **Start Scan**

### Viewing Results

1. Results automatically appear when a scan completes
2. Use the tabs within the Results section to navigate:
   - **Subdomains** - All discovered subdomains
   - **DNS Records** - DNS enumeration results
   - **WHOIS** - Domain registration information
   - **Emails** - Harvested email addresses

### Exporting Reports

1. Go to the **History** tab
2. Find the completed scan
3. Click the download icon to export JSON report

### Comparing Scans

1. Go to the **Tools** tab
2. Select two scans from the dropdown menus
3. Click **Compare Scans** to see differences

---

## Computer Science Concepts

### Networking

| Concept | Application |
|---------|-------------|
| **TCP/IP** | Raw socket connections for banner grabbing |
| **DNS** | Record enumeration and resolution |
| **HTTP/TLS** | Certificate analysis and protocol inspection |
| **OSI Model** | Layer 4-7 protocol parsing |

### Cryptography

| Concept | Application |
|---------|-------------|
| **Symmetric Encryption** | Cipher suite analysis |
| **Asymmetric Encryption** | Public key strength validation |
| **PKI** | Certificate chain validation |
| **Hash Functions** | Hash cracker tool |

### Data Structures

| Concept | Application |
|---------|-------------|
| **Max-Heap** | Vulnerability priority queue (highest CVSS first) |
| **Graph** | Attack surface visualization |
| **Sets** | Deduplication of findings |
| **Queues** | Phase execution pipeline |

### Database Design

| Concept | Application |
|---------|-------------|
| **Relational Model** | Normalized data storage |
| **Indexing** | Fast CVE lookup |
| **Foreign Keys** | Data integrity |
| **JSON Storage** | Flexible schema for varied results |

### Operating Systems

| Concept | Application |
|---------|-------------|
| **Process Management** | Async scan execution |
| **Thread Pool** | Rate limiting implementation |
| **File I/O** | Report generation |
| **Scheduling** | Scan queue management |

---

## Security Considerations

### Data Protection

- All scan data stored locally in SQLite
- No external API calls without explicit configuration
- Audit logging for accountability

### Safe Mode

The platform operates in safe mode by default:
- No destructive exploits executed
- Proof-of-concept capture only
- Safeguards against unintended damage

### Rate Limiting

Built-in rate limiting to:
- Avoid triggering IDS/IPS
- Prevent denial of service
- Maintain low profile during reconnaissance

---

## Future Enhancements

### Planned Features

- [ ] **PDF Report Generation** - Using ReportLab
- [ ] **WebSocket Real-time Updates** - Live progress without polling
- [ ] **Multi-target Parallel Scanning** - Concurrent scan execution
- [ ] **Scheduled Scans** - Cron-based automation
- [ ] **Shodan API Integration** - Enhanced OSINT
- [ ] **Metasploit Integration** - Real exploitation capabilities
- [ ] **Custom Wordlists** - User-defined subdomain enumeration
- [ ] **API Authentication** - JWT-based security
- [ ] **Team Collaboration** - Multi-user support
- [ ] **Scan Templates** - Pre-configured scan profiles

---

## License

This project is developed for educational purposes as part of a Cybersecurity Lab course at VJTI Computer Engineering.

---

## Contributors

- VJTI Computer Engineering - Cybersecurity Lab

---

## Acknowledgments

- NIST Cybersecurity Framework
- CIS Controls
- OWASP Testing Guide
- MITRE ATT&CK Framework
