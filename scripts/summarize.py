#!/usr/bin/env python3
"""Resume results/raw/*.jsonl en results/SUMMARY.md y results/summary.json.

Para cada (red, grupo, resumption) toma la mediana entre rondas de cada
métrica. Si la red declara un RTT (rttNN), verifica que la p50 medida sea
>= 2*RTT (TCP connect + vuelo TLS 1.3 con eco); si no, netem no se aplicó y
el script falla.
"""
import glob, json, os, re, statistics, sys

root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
rows = []
for f in sorted(glob.glob(os.path.join(root, "raw", "*.jsonl"))):
    with open(f) as fh:
        rows += [json.loads(l) for l in fh if l.strip()]
if not rows:
    sys.exit("FATAL: no hay results/raw/*.jsonl")

M = ["handshakes_per_s", "client_cpu_us_per_hs", "server_cpu_us_per_hs", "client_hello_bytes",
     "bytes_c2s_per_hs", "bytes_s2c_per_hs", "p50_us", "p99_us", "p999_us"]
groups = {}
for r in rows:
    groups.setdefault((r["net"], r["resumption"], r["group"]), []).append(r)

summary, errors = [], []
for (net, res, g), rs in sorted(groups.items()):
    s = {"net": net, "resumption": res, "group": g, "reps": len(rs), "n_per_rep": rs[0]["handshakes"]}
    for m in M:
        s[m] = statistics.median(x[m] for x in rs)
    s["handshakes_per_s_min"] = min(x["handshakes_per_s"] for x in rs)
    s["handshakes_per_s_max"] = max(x["handshakes_per_s"] for x in rs)
    m_rtt = re.search(r"rtt(\d+)", net)
    if m_rtt:
        floor_us = 2 * int(m_rtt.group(1)) * 1000
        if s["p50_us"] < floor_us:
            errors.append(f"{net}/{g}/res={res}: p50 {s['p50_us']:.0f}us < {floor_us}us: netem no se aplicó")
    summary.append(s)

def find(net, res, g):
    return next(x for x in summary if x["net"] == net and x["resumption"] == res and x["group"] == g)

lines = ["# Resumen (mediana entre rondas)", "",
         "Generado por `scripts/summarize.py` desde `results/raw/*.jsonl`. "
         "CPU = user+sys por hilo (getrusage RUSAGE_THREAD); latencia = TCP connect + handshake mTLS + eco de 1 byte.", ""]
for net in sorted({x["net"] for x in summary}):
    lines += [f"## Red: `{net}`", "",
              "| modo | grupo | hs/s (mín–máx) | CPU cliente µs/hs | CPU servidor µs/hs | ClientHello B | B c→s/hs | B s→c/hs | p50 µs | p99 µs | p99.9 µs |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
    for res in (False, True):
        for g in ("X25519", "X25519MLKEM768"):
            try:
                s = find(net, res, g)
            except StopIteration:
                continue
            lines.append(f"| {'resumption' if res else 'completo'} | {g} | {s['handshakes_per_s']:.0f} ({s['handshakes_per_s_min']:.0f}–{s['handshakes_per_s_max']:.0f}) | "
                         f"{s['client_cpu_us_per_hs']:.1f} | {s['server_cpu_us_per_hs']:.1f} | {s['client_hello_bytes']:.0f} | "
                         f"{s['bytes_c2s_per_hs']:.0f} | {s['bytes_s2c_per_hs']:.0f} | {s['p50_us']:.0f} | {s['p99_us']:.0f} | {s['p999_us']:.0f} |")
    lines.append("")
    lines += ["Híbrido / X25519 (mediana):", ""]
    for res in (False, True):
        try:
            a, b = find(net, res, "X25519"), find(net, res, "X25519MLKEM768")
        except StopIteration:
            continue
        r = lambda m: b[m] / a[m]
        lines.append(f"- {'resumption' if res else 'completo'}: hs/s x{r('handshakes_per_s'):.3f}, "
                     f"CPU cliente x{r('client_cpu_us_per_hs'):.3f}, CPU servidor x{r('server_cpu_us_per_hs'):.3f}, "
                     f"bytes c→s +{b['bytes_c2s_per_hs']-a['bytes_c2s_per_hs']:.0f}, s→c +{b['bytes_s2c_per_hs']-a['bytes_s2c_per_hs']:.0f}, "
                     f"p50 x{r('p50_us'):.3f}, p99 x{r('p99_us'):.3f}")
    lines.append("")

with open(os.path.join(root, "SUMMARY.md"), "w") as fh:
    fh.write("\n".join(lines))
with open(os.path.join(root, "summary.json"), "w") as fh:
    json.dump(summary, fh, indent=1, sort_keys=True)
print("\n".join(lines))
if errors:
    print("\n".join("FATAL: " + e for e in errors), file=sys.stderr)
    sys.exit(1)
