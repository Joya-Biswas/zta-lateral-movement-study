#!/bin/bash
# rebuild_testbed.sh — Rebuilds entire ZTA namespace testbed from scratch
# Run with: sudo bash /home/kali/zta_experiment/rebuild_testbed.sh

set -e
echo "=== Rebuilding ZTA Testbed ==="

# ── 1. Create namespaces ──────────────────────────────────────────────────────
for ns in ns_attacker ns_dmz ns_workstation1 ns_workstation2 ns_workstation3 ns_workstation4 ns_dc ns_fileserver; do
    ip netns add $ns 2>/dev/null || true
    echo "  + namespace: $ns"
done

# ── 2. Create veth pairs ──────────────────────────────────────────────────────
declare -A VETHS=(
    [veth_att0]="veth_att1 ns_attacker"
    [veth_dmz0]="veth_dmz1 ns_dmz"
    [veth_ws10]="veth_ws11 ns_workstation1"
    [veth_ws20]="veth_ws21 ns_workstation2"
    [veth_ws30]="veth_ws31 ns_workstation3"
    [veth_ws40]="veth_ws41 ns_workstation4"
    [veth_dc0]="veth_dc1 ns_dc"
    [veth_fs0]="veth_fs1 ns_fileserver"
)

ip link add veth_att0  type veth peer name veth_att1  2>/dev/null || true
ip link add veth_dmz0  type veth peer name veth_dmz1  2>/dev/null || true
ip link add veth_ws10  type veth peer name veth_ws11  2>/dev/null || true
ip link add veth_ws20  type veth peer name veth_ws21  2>/dev/null || true
ip link add veth_ws30  type veth peer name veth_ws31  2>/dev/null || true
ip link add veth_ws40  type veth peer name veth_ws41  2>/dev/null || true
ip link add veth_dc0   type veth peer name veth_dc1   2>/dev/null || true
ip link add veth_fs0   type veth peer name veth_fs1   2>/dev/null || true
echo "  + veth pairs created"

# ── 3. Create bridges ─────────────────────────────────────────────────────────
ip link add br_internal type bridge 2>/dev/null || true
ip link add br_servers  type bridge 2>/dev/null || true

# Attach host-side veths to bridges
ip link set veth_ws10 master br_internal
ip link set veth_ws20 master br_internal
ip link set veth_ws30 master br_internal
ip link set veth_ws40 master br_internal
ip link set veth_dc0  master br_servers
ip link set veth_fs0  master br_servers
echo "  + bridges created"

# ── 4. Move namespace-side veths into namespaces ──────────────────────────────
ip link set veth_att1 netns ns_attacker
ip link set veth_dmz1 netns ns_dmz
ip link set veth_ws11 netns ns_workstation1
ip link set veth_ws21 netns ns_workstation2
ip link set veth_ws31 netns ns_workstation3
ip link set veth_ws41 netns ns_workstation4
ip link set veth_dc1  netns ns_dc
ip link set veth_fs1  netns ns_fileserver
echo "  + veths assigned to namespaces"

# ── 5. Assign IP addresses ────────────────────────────────────────────────────
ip netns exec ns_attacker   ip addr add 10.0.0.2/24   dev veth_att1
ip netns exec ns_dmz        ip addr add 10.0.1.2/24   dev veth_dmz1
ip netns exec ns_workstation1 ip addr add 10.0.2.10/24 dev veth_ws11
ip netns exec ns_workstation2 ip addr add 10.0.2.11/24 dev veth_ws21
ip netns exec ns_workstation3 ip addr add 10.0.2.12/24 dev veth_ws31
ip netns exec ns_workstation4 ip addr add 10.0.2.13/24 dev veth_ws41
ip netns exec ns_dc         ip addr add 10.0.3.10/24  dev veth_dc1
ip netns exec ns_fileserver ip addr add 10.0.3.11/24  dev veth_fs1

# Bridge IPs (router function)
ip addr add 10.0.2.1/24 dev br_internal 2>/dev/null || true
ip addr add 10.0.3.1/24 dev br_servers  2>/dev/null || true
echo "  + IP addresses assigned"

# ── 6. Bring all interfaces up ────────────────────────────────────────────────
for iface in br_internal br_servers veth_ws10 veth_ws20 veth_ws30 veth_ws40 veth_dc0 veth_fs0 veth_att0 veth_dmz0; do
    ip link set $iface up
done
ip netns exec ns_attacker   ip link set veth_att1 up
ip netns exec ns_attacker   ip link set lo up
ip netns exec ns_dmz        ip link set veth_dmz1 up
ip netns exec ns_workstation1 ip link set veth_ws11 up
ip netns exec ns_workstation1 ip link set lo up
ip netns exec ns_workstation2 ip link set veth_ws21 up
ip netns exec ns_workstation2 ip link set lo up
ip netns exec ns_workstation3 ip link set veth_ws31 up
ip netns exec ns_workstation3 ip link set lo up
ip netns exec ns_workstation4 ip link set veth_ws41 up
ip netns exec ns_workstation4 ip link set lo up
ip netns exec ns_dc         ip link set veth_dc1 up
ip netns exec ns_dc         ip link set lo up
ip netns exec ns_fileserver ip link set veth_fs1 up
ip netns exec ns_fileserver ip link set lo up
echo "  + interfaces up"

# ── 7. Enable IP forwarding ───────────────────────────────────────────────────
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# ── 8. Add default routes inside namespaces ───────────────────────────────────
ip netns exec ns_workstation1 ip route add default via 10.0.2.1
ip netns exec ns_workstation2 ip route add default via 10.0.2.1
ip netns exec ns_workstation3 ip route add default via 10.0.2.1
ip netns exec ns_workstation4 ip route add default via 10.0.2.1
ip netns exec ns_dc         ip route add default via 10.0.3.1
ip netns exec ns_fileserver ip route add default via 10.0.3.1
ip netns exec ns_attacker   ip route add 10.0.2.0/24 via 10.0.2.1 dev veth_att1 2>/dev/null || true
ip netns exec ns_attacker   ip route add 10.0.3.0/24 via 10.0.3.1 dev veth_att1 2>/dev/null || true
echo "  + routes configured"

# ── 9. Quick connectivity test ────────────────────────────────────────────────
echo ""
echo "=== Connectivity Test ==="
for target in 10.0.2.10 10.0.2.11 10.0.3.10 10.0.3.11; do
    if ip netns exec ns_workstation1 ping -c1 -W1 $target &>/dev/null; then
        echo "  ✓ $target reachable"
    else
        echo "  ✗ $target UNREACHABLE"
    fi
done

echo ""
echo "=== Testbed Ready ==="
ip netns list
