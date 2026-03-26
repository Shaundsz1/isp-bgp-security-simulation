#!/usr/bin/env python3

"""
BGP Health Monitor & Hijack Detector
Author: Shaun Dsouza
Project: ISP Simulation with BGP Security & Automation
"""
import subprocess, re, sys
from datetime import datetime

ROUTERS = {
    "R1-Alpha-Edge": {"container_id": None, "asn": 100, "expected_peers": 2},
    "R2-Alpha-Core": {"container_id": None, "asn": 100, "expected_peers": 3},
    "R3-Bravo-Edge": {"container_id": None, "asn": 200, "expected_peers": 2},
    "R4-Bravo-Core": {"container_id": None, "asn": 200, "expected_peers": 3},
    "R5-Charlie":    {"container_id": None, "asn": 300, "expected_peers": 3},
    "R6-Customer":   {"container_id": None, "asn": 400, "expected_peers": 2},
    "R7-Attacker":   {"container_id": None, "asn": 500, "expected_peers": 1}
}

PREFIX_REGISTRY = {
    "100.100.0.0/16": 100, "200.200.0.0/16": 200,
    "150.150.0.0/16": 300, "172.16.0.0/16": 400, "10.10.10.0/24": 500
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

def status(name, st, detail=""):
    icons = {"OK": "✅", "WARN": "⚠️ ", "FAIL": "❌"}
    print(f"  {icons.get(st, '?')} {name}" + (f" — {detail}" if detail else ""))

def discover():
    banner("DISCOVERING ROUTER CONTAINERS")
    output = run_cmd("docker ps -q")
    if not output:
        print("  No running containers!")
        sys.exit(1)
    found = 0
    for cid in output.split("\n"):
        h = run_cmd(f"docker exec {cid} hostname 2>/dev/null")
        if h in ROUTERS:
            ROUTERS[h]["container_id"] = cid
            print(f"  Found {h} -> {cid[:12]}")
            found += 1
    print(f"\n  Discovered {found}/{len(ROUTERS)} routers")
    return found

def check_peers():
    banner("CHECK 1: BGP PEER HEALTH")
    issues = 0
    for name, r in ROUTERS.items():
        if not r["container_id"]:
            status(name, "FAIL", "Container not found"); issues += 1; continue
        out = vtysh(r["container_id"], "show ip bgp summary")
        if not out:
            status(name, "FAIL", "Cannot reach"); issues += 1; continue
        est, down = 0, []
        for line in out.split("\n"):
            if re.match(r'^\d+\.\d+\.\d+\.\d+', line.strip()):
                parts = line.split()
                if len(parts) >= 10:
                    if parts[9].isdigit(): est += 1
                    else: down.append(f"{parts[0]}({parts[9]})")
        exp = r["expected_peers"]
        if est == exp: status(name, "OK", f"{est}/{exp} peers up (AS {r['asn']})")
        elif est > 0: status(name, "WARN", f"{est}/{exp} up, DOWN: {', '.join(down)}"); issues += 1
        else: status(name, "FAIL", f"0/{exp} — ALL DOWN!"); issues += 1
    return issues

def check_prefixes():
    banner("CHECK 2: PREFIX COUNT VALIDATION")
    issues, expected = 0, len(PREFIX_REGISTRY)
    for name, r in ROUTERS.items():
        if not r["container_id"]: continue
        out = vtysh(r["container_id"], "show ip bgp")
        if not out: issues += 1; continue
        pfx = set()
        for line in out.split("\n"):
            m = re.match(r'^[\s*>=id]+(\d+\.\d+\.\d+\.\d+/\d+)', line)
            if m: pfx.add(m.group(1))
        c = len(pfx)
        if c == expected: status(name, "OK", f"{c} prefixes (expected {expected})")
        elif c > expected: status(name, "WARN", f"{c} prefixes — EXTRA ROUTES!"); issues += 1
        else: status(name, "WARN", f"{c} prefixes — missing routes"); issues += 1
    return issues

def get_as_path(cid, prefix):
    """Get the AS path for a specific prefix using detailed view."""
    out = vtysh(cid, f"show ip bgp {prefix}")
    for line in out.split("\n"):
        line = line.strip()
        # Look for the AS path line - contains just AS numbers and origin code

        if re.match(r'^\d+(\s+\d+)*\s*[ie?]?$', line):
            nums = re.findall(r'\b(\d+)\b', line)
            return [int(n) for n in nums]
        # Also check for "Local" indication

        if "locally originated" in line.lower() or "weight 32768" in line:
            return []
    return []

def is_subnet(child, parent):
    try:
        cn, cm = child.split("/"); pn, pm = parent.split("/")
        if int(cm) <= int(pm): return False
        cp = list(map(int, cn.split("."))); pp = list(map(int, pn.split(".")))
        mb = int(pm)
        for i in range(4):
            bits = min(8, max(0, mb - i * 8))
            mask = (0xFF << (8 - bits)) & 0xFF
            if (cp[i] & mask) != (pp[i] & mask): return False
        return True
    except: return False

def check_hijack():
    banner("CHECK 3: BGP HIJACK DETECTION (RPKI-style)")
    hijacks = 0
    v = ROUTERS.get("R2-Alpha-Core", {})
    if not v.get("container_id"):
        print("  Cannot find vantage point"); return 1
    cid = v["container_id"]
    print(f"  Vantage point: R2-Alpha-Core (AS 100)")
    print(f"  Checking {len(PREFIX_REGISTRY)} registered prefixes...\n")

    out = vtysh(cid, "show ip bgp")
    if not out: return 1

    # Get all unique prefixes from BGP table

    prefixes = set()
    for line in out.split("\n"):
        m = re.match(r'^[\s*>=id]+(\d+\.\d+\.\d+\.\d+/\d+)', line)
        if m: prefixes.add(m.group(1))

    for prefix in sorted(prefixes):
        as_path = get_as_path(cid, prefix)

        if not as_path:
            # Locally originated

            if prefix in PREFIX_REGISTRY and PREFIX_REGISTRY[prefix] == v["asn"]:
                status(prefix, "OK", f"Origin AS {v['asn']} — LOCAL/VALID")
            elif prefix in PREFIX_REGISTRY:
                status(prefix, "FAIL", f"Locally originated but registered to AS {PREFIX_REGISTRY[prefix]}!")
                hijacks += 1
            continue

        origin_as = as_path[-1]
        if prefix in PREFIX_REGISTRY:
            exp = PREFIX_REGISTRY[prefix]
            if origin_as == exp:
                status(prefix, "OK", f"Origin AS {origin_as} — VALID (path: {' → '.join(map(str, as_path))})")
            else:
                status(prefix, "FAIL", f"Origin AS {origin_as} — EXPECTED AS {exp} — HIJACK!")
                hijacks += 1
        else:
            for rp, ra in PREFIX_REGISTRY.items():
                if is_subnet(prefix, rp) and origin_as != ra:
                    status(prefix, "FAIL", f"Origin AS {origin_as} — MORE-SPECIFIC HIJACK of {rp}!")
                    hijacks += 1
                    break
            else:
                status(prefix, "WARN", f"Origin AS {origin_as} — NOT IN REGISTRY")

    print(f"\n  {'🚨 ' + str(hijacks) + ' HIJACK(S) DETECTED!' if hijacks else '✅ No hijacks detected — all prefixes valid'}")
    return hijacks

def check_paths():
    banner("CHECK 4: ROUTE PATH ANALYSIS")
    issues = 0
    v = ROUTERS.get("R2-Alpha-Core", {})
    if not v.get("container_id"): return 1
    cid = v["container_id"]

    out = vtysh(cid, "show ip bgp")
    if not out: return 1

    prefixes = set()
    for line in out.split("\n"):
        m = re.match(r'^[\s*>=id]+(\d+\.\d+\.\d+\.\d+/\d+)', line)
        if m: prefixes.add(m.group(1))

    for prefix in sorted(prefixes):
        as_path = get_as_path(cid, prefix)
        path_str = " → ".join(map(str, as_path)) if as_path else "LOCAL"
        path_len = len(as_path)

        if path_len > 4:
            status(prefix, "WARN", f"Long path ({path_len} hops): {path_str}")
            issues += 1
        elif as_path and len(set(as_path)) != len(as_path):
            status(prefix, "FAIL", f"AS PATH LOOP: {path_str}")
            issues += 1
        else:
            status(prefix, "OK", f"Path ({path_len} hops): {path_str}")
    return issues

def main():
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "=" * 58)
    print(f"  BGP HEALTH MONITOR & HIJACK DETECTOR")
    print(f"  ISP Simulation — Shaun Dsouza")
    print(f"  Scan Time: {ts}")
    print("=" * 58)
    found = discover()
    if found == 0:
        print("\nNo routers found!"); sys.exit(1)
    issues = check_peers() + check_prefixes() + check_hijack() + check_paths()
    banner("SCAN SUMMARY")
    if issues == 0: print("  ✅ ALL CHECKS PASSED — Network is healthy!")
    else: print(f"  ⚠️  {issues} issue(s) detected — review above")
    print(f"\n  Scan completed at {datetime.now().strftime('%H:%M:%S')}\n")

if __name__ == "__main__":
    main()
