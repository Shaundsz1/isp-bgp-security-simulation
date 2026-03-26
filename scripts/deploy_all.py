#!/usr/bin/env python3
"""
One-Command Full Topology Deployer
====================================
Reads the Ansible inventory YAML, generates FRR configs
using Jinja2 templates, and deploys to all Docker containers.
Solves the Docker persistence problem — rebuild everything in seconds.

Author: Shaun Dsouza
Project: ISP Simulation with BGP Security & Automation
"""
import subprocess, yaml, sys, os
from jinja2 import Template
from datetime import datetime

INVENTORY = os.path.expanduser("~/isp-simulation/ansible/inventory.yml")
TEMPLATE = os.path.expanduser("~/isp-simulation/ansible/frr_config.j2")

def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except:
        return ""

def banner(t):
    print("\n" + "=" * 60 + f"\n  {t}\n" + "=" * 60)

def discover():
    routers = {}
    for cid in run_cmd("docker ps -q").split("\n"):
        if not cid: continue
        h = run_cmd(f"docker exec {cid} hostname 2>/dev/null")
        if h and h != "FW1-Firewall":
            routers[h] = cid
    return routers

def load_inventory():
    with open(INVENTORY) as f:
        inv = yaml.safe_load(f)
    hosts = {}
    for group_name, group in inv["all"]["children"].items():
        for hostname, vars in group["hosts"].items():
            vars["hostname"] = hostname
            hosts[hostname] = vars
    return hosts

def load_template():
    with open(TEMPLATE) as f:
        return Template(f.read())

def enable_daemons(cid, hostname):
    run_cmd(f"docker exec {cid} sed -i 's/bgpd=no/bgpd=yes/' /etc/frr/daemons")
    run_cmd(f"docker exec {cid} sed -i 's/ospfd=no/ospfd=yes/' /etc/frr/daemons")
    bgp = run_cmd(f"docker exec {cid} pgrep bgpd 2>/dev/null")
    ospf = run_cmd(f"docker exec {cid} pgrep ospfd 2>/dev/null")
    if not bgp:
        run_cmd(f"docker exec {cid} /usr/lib/frr/bgpd -d -A 127.0.0.1 2>/dev/null")
    if not ospf:
        run_cmd(f"docker exec {cid} /usr/lib/frr/ospfd -d -A 127.0.0.1 2>/dev/null")

def deploy_config(cid, hostname, config):
    # Write config line by line via vtysh
    lines = [l.strip() for l in config.split("\n") if l.strip() and not l.strip().startswith("!")]
    config_block = "\n".join(lines)
    cmd = f'docker exec {cid} vtysh -c "{config_block}" 2>/dev/null'
    result = run_cmd(cmd)
    return result

def main():
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "=" * 58)
    print(f"  ISP TOPOLOGY DEPLOYER")
    print(f"  One-command full network rebuild")
    print(f"  Shaun Dsouza — {ts}")
    print("=" * 58)

    # Step 1: Discover containers
    banner("STEP 1: DISCOVERING CONTAINERS")
    containers = discover()
    if not containers:
        print("  No containers found!"); sys.exit(1)
    for name, cid in sorted(containers.items()):
        print(f"  Found {name} -> {cid[:12]}")
    print(f"\n  {len(containers)} routers discovered")

    # Step 2: Load inventory and template
    banner("STEP 2: LOADING INVENTORY & TEMPLATE")
    hosts = load_inventory()
    template = load_template()
    print(f"  Loaded {len(hosts)} host definitions")
    print(f"  Template: {TEMPLATE}")

    # Step 3: Enable daemons
    banner("STEP 3: ENABLING FRR DAEMONS")
    for hostname, cid in sorted(containers.items()):
        enable_daemons(cid, hostname)
        daemons = run_cmd(f'docker exec {cid} vtysh -c "show daemons" 2>/dev/null')
        has_bgp = "bgpd" in daemons
        has_ospf = "ospfd" in daemons
        icon = "✅" if has_bgp and has_ospf else "⚠️"
        print(f"  {icon} {hostname}: {daemons.strip()}")

    # Step 4: Generate and deploy configs
    banner("STEP 4: GENERATING & DEPLOYING CONFIGS")
    success, failed = 0, 0
    for hostname in sorted(hosts.keys()):
        if hostname not in containers:
            print(f"  ❌ {hostname} — container not found, skipping")
            failed += 1
            continue

        cid = containers[hostname]
        host_vars = hosts[hostname]

        # Generate config from template
        config = template.render(**host_vars)

        # Deploy
        result = deploy_config(cid, hostname, config)

        # Verify
        bgp_check = run_cmd(f'docker exec {cid} vtysh -c "show ip bgp summary" 2>/dev/null')
        if "router bgp" in run_cmd(f'docker exec {cid} vtysh -c "show running-config" 2>/dev/null'):
            print(f"  ✅ {hostname} — deployed successfully")
            success += 1
        else:
            print(f"  ⚠️  {hostname} — deployed (verify manually)")
            success += 1

    # Step 5: Wait for convergence
    banner("STEP 5: WAITING FOR BGP CONVERGENCE")
    print("  Waiting 20 seconds...")
    import time
    time.sleep(20)

    # Step 6: Verify
    banner("STEP 6: VERIFICATION")
    for hostname, cid in sorted(containers.items()):
        summary = run_cmd(f'docker exec {cid} vtysh -c "show ip bgp summary" 2>/dev/null')
        peers = 0
        for line in summary.split("\n"):
            if line.strip() and line.strip()[0].isdigit():
                parts = line.split()
                if len(parts) >= 10 and parts[9].isdigit():
                    peers += 1
        total_line = [l for l in summary.split("\n") if "Total" in l]
        total = total_line[0].split()[-1] if total_line else "?"
        icon = "✅" if peers > 0 else "❌"
        print(f"  {icon} {hostname}: {peers}/{total} BGP peers established")

    # Summary
    banner("DEPLOYMENT COMPLETE")
    print(f"  Routers configured: {success}")
    print(f"  Failed: {failed}")
    print(f"  Run 'python3 ~/bgp_monitor.py' to verify full health\n")

if __name__ == "__main__":
    main()
