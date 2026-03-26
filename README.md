# ISP Network Simulation with BGP Security & Automation

> Multi-AS Internet Service Provider simulation featuring BGP hijacking attack/defense demonstration, zone-based firewall, and full infrastructure-as-code automation.

**Author:** Shaun Dsouza | Master's in ECE, Northeastern University
**Platform:** GNS3 + FRRouting (Docker) on Apple Silicon
**Duration:** 3-week build

---

## What This Project Demonstrates

This project simulates a realistic ISP backbone with 5 autonomous systems, then demonstrates a **BGP prefix hijacking attack** — one of the most dangerous threats to internet routing — followed by multi-layered defenses. The entire infrastructure is automated with Python and deployable from a single command.

### Skills Showcased
- **BGP/OSPF Routing** — eBGP multi-AS peering, iBGP with route reflectors, OSPF as IGP
- **Network Security** — BGP hijack attack/defense, prefix filtering, MD5 authentication
- **Firewall Administration** — iptables zone-based policies, NAT, stateful packet filtering
- **Network Automation** — Python/Jinja2 config generation, automated deployment, health monitoring
- **Infrastructure as Code** — YAML-defined topology, one-command rebuild, compliance checking

---

## Network Architecture

```
         ┌──────────┐        eBGP        ┌──────────┐
         │   R1     │◄──────────────────►│   R3     │
         │ AS 100   │                    │ AS 200   │
         │ISP-Alpha │                    │ISP-Bravo │
         └────┬─────┘                    └────┬─────┘
              │ iBGP/OSPF                     │ iBGP/OSPF
         ┌────┴─────┐        eBGP        ┌────┴─────┐
         │   R2     │◄──────────────────►│   R4     │
         │ AS 100   │                    │ AS 200   │
         └────┬─────┘                    └──┬───┬───┘
              │ eBGP                   eBGP │   │
         ┌────┴─────┐        eBGP     ┌────┴──┐│FW1│
         │   R5     │◄──────────────►│  R6   ││   │
         │ AS 300   │                │ AS 400││   │
         │ISP-Charlie│                │Customer│└───┘
         └────┬─────┘                └────────┘
              │ eBGP
         ┌────┴─────┐
         │   R7     │
         │ AS 500   │
         │ Attacker │
         └──────────┘
```

| AS | Name | Routers | Role |
|----|------|---------|------|
| 100 | ISP-Alpha | R1 (Edge), R2 (Core) | Transit ISP |
| 200 | ISP-Bravo | R3 (Edge), R4 (Core) | Transit ISP |
| 300 | ISP-Charlie | R5 | Regional ISP |
| 400 | Customer | R6 | Multi-homed customer |
| 500 | Attacker | R7 | Rogue network |

---

## BGP Hijacking Attack Demo

### The Attack
The attacker (AS 500) announces `172.16.0.0/24` — a more specific prefix than the customer's legitimate `172.16.0.0/16`. Due to BGP's longest-prefix-match rule, **every router on the network** prefers the attacker's route. Traffic destined for the customer is silently redirected to the attacker.

### Before Attack
```
R1 → 172.16.0.0/16 via AS 200 → AS 400 (legitimate path)
```

### During Attack
```
R1 → 172.16.0.0/24 via AS 300 → AS 500 (hijacked!)
All 7 routers poisoned within seconds
```

### Defense Implementation
1. **Prefix-List Filtering** — Only accept authorized prefixes from each neighbor
2. **MD5 Authentication** — Cryptographic BGP session verification
3. **Network-Wide Route Policies** — Defense in depth across all ISP peerings

### After Defense
```
172.16.0.0/24 → "Network not in table" (hijack blocked)
172.16.0.0/16 → AS 200 → AS 400 (legitimate path restored)
```

---

## Firewall

Zone-based Linux firewall (Alpine + iptables) between ISP-Bravo and Customer:

- **Default deny** — DROP all traffic, permit by exception
- **Stateful filtering** — Track connections, allow return traffic
- **NAT/Masquerade** — Source NAT for outbound customer traffic
- **Directional policy** — LAN→WAN allowed, WAN→LAN blocked
- **Logging** — Dropped packets logged for security monitoring

### Verification Results
```
TEST 1: LAN → WAN (R6 → R4):  ✅ 2/2 packets received (ALLOWED)
TEST 2: WAN → LAN (R4 → R6):  ❌ 0/2 packets received (BLOCKED)
```

---

## Automation Tools

### 1. BGP Health Monitor & Hijack Detector (`bgp_monitor.py`)
Real-time network health scanner with 4 automated checks:
- **Peer Health** — Verifies all BGP sessions are established
- **Prefix Validation** — Confirms expected route count per router
- **RPKI-style Hijack Detection** — Validates prefix origins against authorized registry
- **Path Analysis** — Detects AS path loops and anomalies

```
$ python3 bgp_monitor.py

  CHECK 1: BGP PEER HEALTH
  ✅ R1-Alpha-Edge — 2/2 peers up (AS 100)
  ✅ R2-Alpha-Core — 3/3 peers up (AS 100)
  ✅ R3-Bravo-Edge — 2/2 peers up (AS 200)
  ✅ R4-Bravo-Core — 3/3 peers up (AS 200)
  ✅ R5-Charlie — 3/3 peers up (AS 300)
  ✅ R6-Customer — 2/2 peers up (AS 400)
  ✅ R7-Attacker — 1/1 peers up (AS 500)

  CHECK 3: BGP HIJACK DETECTION (RPKI-style)
  ✅ 10.10.10.0/24 — Origin AS 500 — VALID (path: 300 → 500)
  ✅ 100.100.0.0/16 — Origin AS 100 — LOCAL/VALID
  ✅ 150.150.0.0/16 — Origin AS 300 — VALID (path: 300)
  ✅ 172.16.0.0/16 — Origin AS 400 — VALID (path: 200 → 400)
  ✅ 200.200.0.0/16 — Origin AS 200 — VALID (path: 200)

  ✅ No hijacks detected — all prefixes valid

  SCAN SUMMARY
  ✅ ALL CHECKS PASSED — Network is healthy!
```

### 2. Config Backup & Compliance Checker (`config_backup.py`)
- Backs up running configs from all 7 routers
- Validates against security compliance rules (MD5 auth, prefix filtering, OSPF)
- Generates compliance score with detailed findings

```
$ python3 config_backup.py

  PHASE 1: CONFIG BACKUP
  ✅ R1-Alpha-Edge — backed up (700 bytes)
  ✅ R2-Alpha-Core — backed up (1045 bytes)
  ...

  PHASE 2: COMPLIANCE CHECK
  [BGP_AUTH] BGP MD5 authentication on external peers
    ✅ R5-Charlie — COMPLIANT
    ✅ R7-Attacker — COMPLIANT
  [PREFIX_FILTER] Inbound prefix-list on eBGP neighbors
    ✅ R2-Alpha-Core — COMPLIANT
    ✅ R4-Bravo-Core — COMPLIANT
    ✅ R5-Charlie — COMPLIANT

  FINAL REPORT
  Compliance score: 100%
```

### 3. One-Command Topology Deployer (`deploy_all.py`)
Infrastructure-as-code deployment using YAML inventory + Jinja2 templates:
- Discovers running containers automatically
- Enables FRR daemons (BGP, OSPF)
- Generates and deploys configs from Jinja2 templates
- Verifies BGP convergence post-deployment

```
$ python3 deploy_all.py

  STEP 4: GENERATING & DEPLOYING CONFIGS
  ✅ R1-Alpha-Edge — deployed successfully
  ✅ R2-Alpha-Core — deployed successfully
  ✅ R3-Bravo-Edge — deployed successfully
  ✅ R4-Bravo-Core — deployed successfully
  ✅ R5-Charlie — deployed successfully
  ✅ R6-Customer — deployed successfully
  ✅ R7-Attacker — deployed successfully

  STEP 6: VERIFICATION
  ✅ R1-Alpha-Edge: 2/2 BGP peers established
  ✅ R2-Alpha-Core: 3/3 BGP peers established
  ✅ R3-Bravo-Edge: 2/2 BGP peers established
  ✅ R4-Bravo-Core: 3/3 BGP peers established
  ✅ R5-Charlie: 3/3 BGP peers established
  ✅ R6-Customer: 2/2 BGP peers established
  ✅ R7-Attacker: 1/1 BGP peers established

  DEPLOYMENT COMPLETE
  Routers configured: 7 | Failed: 0
```

---

## Project Structure

```
isp-simulation/
├── README.md
├── ansible/
│   ├── inventory.yml          # YAML-defined network topology
│   └── frr_config.j2          # Jinja2 config template
├── scripts/
│   ├── bgp_monitor.py         # BGP health & hijack detector
│   ├── config_backup.py       # Config backup & compliance checker
│   └── deploy_all.py          # One-command topology deployer
├── config_backups/            # Timestamped router config backups
└── docs/
    ├── week1_topology.md      # Foundation — multi-AS routing setup
    ├── week2_security.md      # BGP attack/defense & firewall
    └── week3_automation.md    # Automation & infrastructure as code
```

---

## Technologies Used

| Category | Technologies |
|----------|-------------|
| Simulation | GNS3, Docker, VMware Fusion |
| Routing | FRRouting v8.4, BGP, OSPF |
| Security | iptables, prefix-lists, MD5 authentication |
| Automation | Python 3, Jinja2, YAML |
| Tools | Netmiko, Ansible |
| Platform | macOS Apple Silicon (ARM64) |

---

## How to Run

### Prerequisites
- GNS3 with GNS3 VM (ARM64 v2.2.54)
- VMware Fusion 13
- Docker with `frrouting/frr:v8.4.0` (ARM64) image
- Python 3.8+ with jinja2, pyyaml, netmiko

### Quick Start
```bash
# Deploy entire topology from scratch
python3 scripts/deploy_all.py

# Monitor network health & detect hijacks
python3 scripts/bgp_monitor.py

# Backup configs & run compliance check
python3 scripts/config_backup.py
```

### Simulate the BGP Hijack Attack
```bash
# Launch attack from R7
docker exec <R7_container> vtysh -c "
configure terminal
router bgp 500
 address-family ipv4 unicast
  network 172.16.0.0/24
 exit-address-family
exit
ip route 172.16.0.0/24 Null0
end"

# Run monitor to detect the hijack
python3 scripts/bgp_monitor.py
# Output: ❌ 172.16.0.0/24 — Origin AS 500 — MORE-SPECIFIC HIJACK!
```

---

## Key Learnings

- **BGP's trust model is fragile** — Any AS can announce any prefix, and without active filtering, the entire internet will believe it. This is why organizations like MANRS advocate for universal prefix filtering and RPKI adoption.

- **Longest prefix match is powerful and dangerous** — The same mechanism that makes routing efficient also makes hijacking trivial. A /24 always beats a /16, regardless of AS path length.

- **Infrastructure as Code solves real problems** — Docker containers lose state on restart. YAML-defined topologies with Jinja2 templates enable one-command recovery, eliminating configuration drift.

- **Layered security is essential** — No single defense is sufficient. Prefix filtering, authentication, firewalling, and monitoring each catch different attack vectors.

- **Automation enables operational excellence** — Manual configuration across 7 routers is error-prone and time-consuming. Automated deployment, monitoring, and compliance checking ensure consistency and rapid incident detection.

---

## Real-World Context

This project demonstrates the same attack vectors and defense mechanisms used in production ISP networks:

- **2008 — Pakistan/YouTube**: Pakistan Telecom's /24 announcement for YouTube's prefix took the platform offline globally for 2 hours
- **2018 — Amazon Route 53**: BGP hijack redirected cryptocurrency traffic through unauthorized networks
- **2022 — Russia/Twitter**: Russian networks briefly hijacked Twitter's IP prefixes during geopolitical conflict

The defenses implemented here (prefix filtering, RPKI-style validation, MD5 authentication) are the same controls recommended by MANRS, NIST, and major ISP security frameworks.

---

## Author

**Shaun Dsouza**
Master's in Electrical & Computer Engineering, Northeastern University
Networking | Security | Automation | Infrastructure as Code
