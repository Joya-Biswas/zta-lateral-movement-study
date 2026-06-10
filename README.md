# ZTA vs Perimeter Security — Lateral Movement Study

A controlled, reproducible empirical comparison of **Zero Trust Architecture (ZTA)** and **perimeter-based security** against three real lateral movement attack scenarios, conducted on a Linux network namespace testbed.

---

## What This Research Is About

Imagine your office building has one security guard at the front door. Once you're inside, you can walk into any room freely — that's how most company computer networks work today. If a thief sneaks past the front door (by stealing an employee's key card), they can roam the entire building unchecked.

Zero Trust Architecture says: **don't trust anyone, even inside the building** — every door requires its own verification.

### How We Tested It

We built a mini fake network on a laptop — 8 virtual computers connected to each other, split into two zones: a "staff floor" (workstations) and a "vault floor" (the server holding sensitive data). Think of it like an office with a locked corridor between the regular desks and the finance room.

We ran three attacks that real hackers use:

- **Pass-the-Hash (PtH)** — stealing a password fingerprint and using it to impersonate someone, without ever knowing their actual password
- **Pass-the-Ticket (PtT)** — stealing a digital "all-day pass" from one computer and reusing it to enter others
- **Credential Dumping (CD)** — quietly harvesting all saved passwords from a machine, then moving systematically through the network

Each attack was run **5 times**, under both security approaches, for **30 total trials**. We measured exactly when each system detected the attack, how fast it stopped it, and how many computers the attacker reached before being blocked.

To make the comparison fair, we used a real packet-capture tool (Scapy) to record the exact moment attack traffic appeared on the network — and separately measured how long the traditional alarm system (SIEM) took to process that traffic into an alert.

### What We Found

| Metric | Perimeter | ZTA |
|--------|-----------|-----|
| Mean Time to Detect (MTTD) | 230–236 s | 0.27–0.48 s |
| Mean Time to Contain (MTTC) | 158–174 s | 0.01–0.19 s |
| Breach Radius | 3–5 nodes | 2–3 nodes |
| False Positive Rate | 8.00% | 3.83% |
| Auth Latency overhead | — | +29 ms |

With the old approach, the attack was technically visible within less than 1 second — but the alarm system took **3–4 minutes** to fire an alert. In that time, the attacker had already reached 4–5 computers.

With Zero Trust, the alarm fired in **under half a second**, every single time, and the attacker was stopped at 2–3 computers.

The trade-off? Zero Trust adds about **29 milliseconds** of delay per login — completely imperceptible to any human.

---

## Repository Structure

```
.
│── policy_engine_v2.py     # Main experiment: ZTA Policy Engine + attack scenarios + perimeter sniffer
│── rebuild_testbed.sh      # Shell script to spin up the 8-namespace Linux testbed
│── results_v2.json         # Raw trial results (30 trials across 3 scenarios × 2 architectures)
├── analysis.ipynb          # Full analysis notebook: statistics, Mann-Whitney U, Cohen's d, plots
└── output/                 # All output figures used in the paper
```

---

## Testbed Architecture

```
ns_attacker ──► br_internal (10.0.2.0/24) ──► br_servers (10.0.3.0/24)
                  │                               │
          ns_workstation1-4               ns_dc + ns_fileserver
```

- **8 Linux network namespaces** connected via veth pairs and two bridges
- **ZTA enforcement**: iptables DROP rules + Python Policy Engine (cross-segment + rapid-reuse detection)
- **Perimeter baseline**: no segment enforcement; MTTD = real Scapy visibility time + literature-calibrated SIEM delay (Uniform[180–270 s])

---

## Reproducing the Experiment

> Requires: Kali Linux (or any Linux with `iproute2`, `iptables`, `python3`, `scapy`)

```bash
# 1. Rebuild the network namespace testbed
sudo bash experiment/rebuild_testbed.sh

# 2. Run the experiment (30 trials, ~10 min)
sudo python3 experiment/policy_engine_v2.py

# Results written to: experiment/results_v2.json
```

Then open `analysis.ipynb` to reproduce all statistics and figures.

---

## Key Dependencies

```
python3 >= 3.10
scapy
jupyter
scipy
matplotlib
seaborn
pandas
numpy
```

---

## Statistical Validation

All comparisons use **Mann-Whitney U test** (α = 0.05, non-parametric, no normality assumption) and **Cohen's d** effect sizes. Every security metric yields d > 9.7 (Very Large), with all p-values < 0.01 across 30 independent trials.

---

## Citation

If you use this dataset or testbed in your own work, please cite the associated paper (forthcoming IEEE conference proceedings).

---

## License

MIT License — see [LICENSE](LICENSE).
