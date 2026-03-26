#!/usr/bin/env python3
"""
Network Config Backup & Compliance Checker
============================================
- Backs up running configs from all routers
- Validates compliance against security policies
- Generates a compliance report

Author: Shaun Dsouza
Project: ISP Simulation with BGP Security & Automation
"""
import subprocess, re, os, sys
from datetime import datetime

BACKUP_DIR = os.path.expanduser("~/config_backups")

COMPLIANCE_RULES = {
    "BGP_AUTH": {
        "description": "BGP MD5 authentication on external peers",
        "check": "password",
        "applies_to": ["R5-Charlie", "R7-Attacker"]
    },
    "PREFIX_FILTER": {
        "description": "Inbound prefix-list on eBGP neighbors",
        "check": "prefix-list",
        "applies_to": ["R2-Alpha-Core", "R4-Bravo-Core", "R5-Charlie"]
    },
    "OSPF_ENABLED": {
        "description": "OSPF configured for internal routing",
        "check": "router ospf",
        "applies_to": ["R1-Alpha-Edge", "R2-Alpha-Core", "R3-Bravo-Edge", "R4-Bravo-Core"]
    }
}

def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except:
        return ""

def vtysh(cid, cmd):
    return run_cmd(f'docker exec {cid} vtysh -c "{cmd}" 2>/dev/null')

def banner(t):
    print("\n" + "=" * 60 + f"\n  {t}\n" + "=" * 60)

def discover():
    routers = {}
    output = run_cmd("docker ps -q")
    if not output:
        return routers
    for cid in output.split("\n"):
        h = run_cmd(f"docker exec {cid} hostname 2>/dev/null")
        if h and h != "FW1-Firewall":
            routers[h] = cid
    return routers

def backup_configs(routers):
    banner("PHASE 1: CONFIG BACKUP")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, timestamp)
    os.makedirs(backup_path, exist_ok=True)

    backed_up = 0
    for name, cid in sorted(routers.items()):
        config = vtysh(cid, "show running-config")
        if config:
            filename = os.path.join(backup_path, f"{name}.conf")
            with open(filename, "w") as f:
                f.write(f"! Backup: {name}\n")
                f.write(f"! Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"! Container: {cid[:12]}\n")
                f.write("!" + "=" * 50 + "\n\n")
                f.write(config)
            backed_up += 1
            size = len(config)
            print(f"  ✅ {name} — backed up ({size} bytes)")
        else:
            print(f"  ❌ {name} — FAILED to retrieve config")

    print(f"\n  Saved {backed_up}/{len(routers)} configs to:")
    print(f"  {backup_path}")
    return backup_path

def compliance_check(routers):
    banner("PHASE 2: COMPLIANCE CHECK")
    total_pass, total_fail = 0, 0

    for rule_id, rule in COMPLIANCE_RULES.items():
        print(f"\n  [{rule_id}] {rule['description']}")
        print(f"  " + "-" * 50)

        for name in rule["applies_to"]:
            if name not in routers:
                print(f"    ⚠️  {name} — not found")
                continue

            config = vtysh(routers[name], "show running-config")
            if rule["check"] in config.lower():
                print(f"    ✅ {name} — COMPLIANT")
                total_pass += 1
            else:
                print(f"    ❌ {name} — NON-COMPLIANT")
                total_fail += 1

    return total_pass, total_fail

def config_diff_check(routers):
    banner("PHASE 3: CONFIGURATION ANALYSIS")

    for name, cid in sorted(routers.items()):
        config = vtysh(cid, "show running-config")
        if not config:
            continue

        issues = []
        # Check for missing write memory
        # Check BGP settings
        if "router bgp" in config:
            if "no bgp ebgp-requires-policy" not in config:
                issues.append("Missing 'no bgp ebgp-requires-policy'")
            bgp_neighbors = re.findall(r'neighbor (\S+) remote-as (\d+)', config)
            for neigh, asn in bgp_neighbors:
                # Check if external peers have prefix-lists
                if asn != re.search(r'router bgp (\d+)', config).group(1):
                    if f"neighbor {neigh} prefix-list" not in config:
                        issues.append(f"No prefix-list on eBGP peer {neigh} (AS {asn})")

        if "router ospf" in config:
            if "ospf router-id" not in config:
                issues.append("OSPF missing explicit router-id")

        if issues:
            print(f"  ⚠️  {name}:")
            for issue in issues:
                print(f"      - {issue}")
        else:
            print(f"  ✅ {name} — no issues found")

def main():
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "=" * 58)
    print(f"  NETWORK CONFIG BACKUP & COMPLIANCE CHECKER")
    print(f"  ISP Simulation — Shaun Dsouza")
    print(f"  Run Time: {ts}")
    print("=" * 58)

    routers = discover()
    if not routers:
        print("\n  No routers found!"); sys.exit(1)
    print(f"\n  Found {len(routers)} routers")

    # Phase 1: Backup
    backup_path = backup_configs(routers)

    # Phase 2: Compliance
    passed, failed = compliance_check(routers)

    # Phase 3: Config analysis
    config_diff_check(routers)

    # Summary
    banner("FINAL REPORT")
    print(f"  Configs backed up: {len(routers)}")
    print(f"  Compliance checks: {passed} passed, {failed} failed")
    total = passed + failed
    score = (passed / total * 100) if total > 0 else 0
    print(f"  Compliance score:  {score:.0f}%")
    print(f"\n  Backups saved to: {backup_path}\n")

if __name__ == "__main__":
    main()
