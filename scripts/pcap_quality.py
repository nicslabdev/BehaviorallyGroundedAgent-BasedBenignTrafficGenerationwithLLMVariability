#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_scappy_zeek.py — Combina análisis Scapy + Zeek para calidad + metadata semántica

Uso:
    python pcap_scappy_zeek.py captura.pcap --gap-ms 100 --json salida.json

Requisitos:
    pip install scapy
    zeek debe estar instalado y accesible desde PATH (ejecutar "zeek --version" para comprobar).
"""
import argparse
import json
import math
import statistics
import subprocess
import tempfile
import shutil
import os
import sys
from collections import defaultdict, Counter
from hashlib import blake2b

from scapy.all import PcapReader, Ether, IP, IPv6, TCP, UDP, Raw

# ---------------- utilidades ----------------
def human_bps(bps):
    if bps is None:
        return "n/a"
    units = ["bps","Kbps","Mbps","Gbps","Tbps"]
    i = 0
    v = float(bps)
    while v >= 1000 and i < len(units)-1:
        v /= 1000.0
        i += 1
    return f"{v:.2f} {units[i]}"

def human_bytes(n):
    if n is None:
        return "n/a"
    units = ["B","KB","MB","GB","TB"]
    i = 0
    v = float(n)
    while v >= 1024 and i < len(units)-1:
        v /= 1024.0
        i += 1
    return f"{v:.2f} {units[i]}"

def pct(values, q):
    if not values:
        return None
    values = list(values)
    values.sort()
    k = (len(values)-1) * (q/100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(values[int(k)])
    d0 = values[f] * (c-k)
    d1 = values[c] * (k-f)
    return float(d0 + d1)

def flow_key(pkt):
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        proto = pkt[IP].proto
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
        proto = pkt[IPv6].nh
    else:
        return ("L2", None, None, None, None)

    if TCP in pkt:
        l4 = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        l4 = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    else:
        l4 = f"IP-{proto}"
        sport = dport = None
    return (src, dst, l4, sport, dport)

def tcp_seq_len(pkt):
    if TCP in pkt:
        seg_len = 0
        if Raw in pkt:
            seg_len = len(pkt[Raw].load)
        syn = 1 if pkt[TCP].flags & 0x02 else 0
        fin = 1 if pkt[TCP].flags & 0x01 else 0
        if seg_len == 0 and (syn or fin):
            return 1
        return seg_len
    return 0

# ---------------- Zeek parser (simple) ----------------
def parse_zeek_tsv(path):
    """
    Parsea un archivo de log Zeek (TSV-ish). Devuelve lista de dicts.
    Omite líneas que empiezan por '#'.
    Primera línea no-comment es cabecera (tab-separated).
    """
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        header = None
        for line in f:
            if line.startswith('#'):
                continue
            line = line.rstrip('\n')
            if not line:
                continue
            if header is None:
                header = line.split('\t')
                continue
            cols = line.split('\t')
            # rellenar si faltan cols
            if len(cols) < len(header):
                cols += [""] * (len(header) - len(cols))
            row = dict(zip(header, cols))
            rows.append(row)
    return rows

# ---------------- Análisis Scapy (similar al script original) ----------------
def analyze_pcap_with_scapy(pcap_path, gap_ms=100.0, max_duplicates=1000000):
    gap_thr_s = gap_ms / 1000.0
    total_pkts = 0
    total_bytes = 0
    t0 = None
    t1 = None
    inter_arrivals = []
    last_ts = None
    gaps = 0
    sizes = []
    per_second_bytes = defaultdict(int)
    per_second_pkts = defaultdict(int)
    ethertypes = Counter()
    ip_protos = Counter()
    tcp_top_ports = Counter()
    udp_top_ports = Counter()
    seen_hashes = set()
    dup_count = 0
    tcp_state = defaultdict(lambda: {"next_seq": None})
    tcp_retrans = 0
    tcp_ooo = 0

    reader = PcapReader(pcap_path)
    for pkt in reader:
        ts = float(getattr(pkt, "time", None) or 0.0)
        if t0 is None:
            t0 = ts
        t1 = ts
        wire_len = int(len(bytes(pkt)))
        total_pkts += 1
        total_bytes += wire_len
        sizes.append(wire_len)
        if last_ts is not None:
            dt = ts - last_ts
            if dt >= 0:
                inter_arrivals.append(dt)
                if dt > gap_thr_s:
                    gaps += 1
        last_ts = ts
        sec = int(ts)
        per_second_bytes[sec] += wire_len
        per_second_pkts[sec] += 1
        if Ether in pkt and hasattr(pkt[Ether], "type"):
            ethertypes[pkt[Ether].type] += 1
        if IP in pkt:
            ip_protos[pkt[IP].proto] += 1
        elif IPv6 in pkt:
            ip_protos[pkt[IPv6].nh] += 1
        if TCP in pkt:
            tcp_top_ports[pkt[TCP].sport] += 1
            tcp_top_ports[pkt[TCP].dport] += 1
            k = flow_key(pkt)
            seq = pkt[TCP].seq
            seg_len = tcp_seq_len(pkt)
            state = tcp_state[k]
            if state["next_seq"] is None:
                state["next_seq"] = (seq + seg_len) & 0xFFFFFFFF
            else:
                expected = state["next_seq"]
                if seg_len > 0:
                    # heurística simple
                    if (seq - expected) & 0xFFFFFFFF == 0:
                        state["next_seq"] = (seq + seg_len) & 0xFFFFFFFF
                    else:
                        # diff sign (sin wrap handling complejo)
                        diff = (seq - expected) if seq >= expected else -(expected - seq)
                        if diff < 0:
                            tcp_retrans += 1
                        else:
                            tcp_ooo += 1
        if UDP in pkt:
            udp_top_ports[pkt[UDP].sport] += 1
            udp_top_ports[pkt[UDP].dport] += 1

        if len(seen_hashes) <= max_duplicates:
            h = blake2b(bytes(pkt), digest_size=12).digest()
            if h in seen_hashes:
                dup_count += 1
            else:
                seen_hashes.add(h)
    reader.close()

    duration = (t1 - t0) if (t0 is not None and t1 is not None) else 0.0
    seconds = sorted(per_second_bytes.keys())
    peak_bps = max((per_second_bytes[s]*8 for s in seconds), default=None)
    peak_pps = max((per_second_pkts[s] for s in seconds), default=None)

    inter_arrivals_sorted = sorted(inter_arrivals)
    iat_mean = statistics.fmean(inter_arrivals_sorted) if inter_arrivals_sorted else None
    iat_med = pct(inter_arrivals_sorted, 50) if inter_arrivals_sorted else None
    iat_p95 = pct(inter_arrivals_sorted, 95) if inter_arrivals_sorted else None
    iat_max = max(inter_arrivals_sorted) if inter_arrivals_sorted else None

    sizes_sorted = sorted(sizes)
    sz_mean = statistics.fmean(sizes_sorted) if sizes_sorted else None
    sz_med = pct(sizes_sorted, 50) if sizes_sorted else None
    sz_p95 = pct(sizes_sorted, 95) if sizes_sorted else None
    sz_max = max(sizes_sorted) if sizes_sorted else None

    def ethertype_name(e):
        mapping = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8847: "MPLS", 0x8100: "802.1Q"}
        return mapping.get(e, hex(e))

    def ipproto_name(p):
        mapping = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "ENCAP-IPv6", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6"}
        return mapping.get(p, str(p))

    top_tcp = tcp_top_ports.most_common(10)
    top_udp = udp_top_ports.most_common(10)

    report = {
        "scapy": {
            "total_packets": total_pkts,
            "total_bytes": total_bytes,
            "capture_start_ts": t0,
            "capture_end_ts": t1,
            "duration_seconds": duration,
            "gaps_over_threshold": gaps,
            "gap_threshold_ms": gap_ms,
            "inter_arrival": {"mean_s": iat_mean, "median_s": iat_med, "p95_s": iat_p95, "max_s": iat_max},
            "packet_sizes": {"mean_bytes": sz_mean, "median_bytes": sz_med, "p95_bytes": sz_p95, "max_bytes": sz_max},
            "throughput": {"peak_bps": peak_bps, "peak_pps": peak_pps,
                           "average_bps": (total_bytes*8/duration) if duration > 0 else None,
                           "average_pps": (total_pkts/duration) if duration > 0 else None},
            "duplicates_approx": dup_count,
            "protocols": {"ethertypes": {ethertype_name(k): v for k, v in ethertypes.most_common()},
                          "ip_protocols": {ipproto_name(k): v for k, v in ip_protos.most_common()},
                          "top_tcp_ports": [{"port": p, "count": c} for p, c in top_tcp],
                          "top_udp_ports": [{"port": p, "count": c} for p, c in top_udp]},
            "tcp_quality": {"retransmissions": tcp_retrans, "out_of_order": tcp_ooo,
                            "note": "Heurística simple basada en next_seq por flujo direccional."}
        }
    }
    return report

# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser(description="Analiza PCAP con Scapy + Zeek")
    ap.add_argument("pcap", help="Ruta al archivo .pcap/.pcapng")
    ap.add_argument("--gap-ms", type=float, default=100.0, help="Umbral gap en ms")
    ap.add_argument("--json", default=None, help="Ruta de salida JSON")
    ap.add_argument("--keep-temp", action="store_true", help="No borra directorio temporal (útil para depuración)")
    args = ap.parse_args()

    pcap_path = args.pcap
    if not os.path.exists(pcap_path):
        print(f"[ERROR] No existe: {pcap_path}")
        sys.exit(1)

    # 1) Ejecutar Zeek en un tmpdir
    tmpdir = tempfile.mkdtemp(prefix="zeek_pcap_")
    try:
        # copiar pcap al tmpdir para que Zeek genere logs ahí
        local_pcap = os.path.join(tmpdir, "input.pcap")
        shutil.copy2(pcap_path, local_pcap)

        # comprobar que zeek está en PATH
        try:
            subprocess.run(["zeek", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print("[WARN] Zeek no encontrado en PATH. Salvo que instales Zeek, se ejecutará sólo Scapy.")
            zeek_ok = False
        else:
            zeek_ok = True

        if zeek_ok:
            print("[INFO] Ejecutando Zeek (puede tardar unos segundos)...")
            # Ejecutar Zeek en el tmpdir (Zeek escribe logs en el cwd)
            try:
                subprocess.run(["zeek", "-C", "-r", "input.pcap"], cwd=tmpdir, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
            except subprocess.CalledProcessError as e:
                print(f"[WARN] Zeek falló: {e}. Se continuará sólo con Scapy.")
                zeek_ok = False
            except subprocess.TimeoutExpired:
                print("[WARN] Zeek excedió tiempo (timeout). Continuando sólo con Scapy.")
                zeek_ok = False

        # 2) Analizar con Scapy
        print("[INFO] Analizando pcap con Scapy...")
        scapy_report = analyze_pcap_with_scapy(local_pcap, gap_ms=args.gap_ms)
        final_report = {"file": os.path.abspath(pcap_path), "scapy_report": scapy_report["scapy"]}

        # 3) Si Zeek generó logs, parsearlos y agregarlos
        if zeek_ok:
            # Parsear conn.log (si existe)
            conn_path = os.path.join(tmpdir, "conn.log")
            conn_rows = parse_zeek_tsv(conn_path)
            summary = {}
            if conn_rows:
                total_conns = len(conn_rows)
                services = Counter()
                servers = Counter()
                clients = Counter()
                total_conn_bytes = 0.0
                durations = []
                for r in conn_rows:
                    svc = r.get("service", "-")
                    services[svc] += 1
                    # zeek usa id.resp_h / id.orig_h
                    resp = r.get("id.resp_h", "")
                    orig = r.get("id.orig_h", "")
                    if resp:
                        servers[resp] += 1
                    if orig:
                        clients[orig] += 1
                    # bytes y duration (puede ser "-" si no aplica)
                    try:
                        ob = float(r.get("orig_bytes","0")) if r.get("orig_bytes","-") != "-" else 0.0
                        rb = float(r.get("resp_bytes","0")) if r.get("resp_bytes","-") != "-" else 0.0
                        total_conn_bytes += (ob + rb)
                    except:
                        pass
                    try:
                        d = float(r.get("duration","0")) if r.get("duration","-") != "-" else 0.0
                        durations.append(d)
                    except:
                        pass
                summary = {
                    "total_connections": total_conns,
                    "unique_servers": len(servers),
                    "unique_clients": len(clients),
                    "top_services": services.most_common(10),
                    "top_servers": servers.most_common(10),
                    "top_clients": clients.most_common(10),
                    "total_conn_bytes": total_conn_bytes,
                    "avg_conn_duration_s": statistics.mean(durations) if durations else None,
                    "median_conn_duration_s": pct(durations, 50) if durations else None
                }
            else:
                summary = {"note": "conn.log no encontrado o vacío."}

            final_report["zeek"] = {"conn_summary": summary}

            # también incluimos logs disponibles (lista de nombres)
            available_logs = [f for f in os.listdir(tmpdir) if f.endswith(".log")]
            final_report["zeek"]["logs_generated"] = available_logs

        else:
            final_report["zeek"] = {"note": "Zeek no se ejecutó / no está disponible."}

        # 4) Exportar JSON si se pidió
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(final_report, fh, ensure_ascii=False, indent=2)
            print(f"[OK] Exportado JSON → {args.json}")

        # 5) Resumen en consola
        sc = final_report["scapy_report"]
        print("\n=== Resumen Scapy ===")
        print(f"Paquetes: {sc['total_packets']:,}  |  Bytes: {sc['total_bytes']:,} ({human_bytes(sc['total_bytes'])})")
        if sc["duration_seconds"]:
            print(f"Duración: {sc['duration_seconds']:.3f} s")
        print(f"Gaps > {sc['gap_threshold_ms']} ms: {sc['gaps_over_threshold']}")
        print(f"Throughput pico: {human_bps(sc['throughput']['peak_bps'])}  |  medio: {human_bps(sc['throughput']['average_bps'])}")
        print(f"Retransmisiones TCP (heurística): {sc['tcp_quality']['retransmissions']}")
        print(f"Out-of-order TCP (heurística): {sc['tcp_quality']['out_of_order']}")
        if zeek_ok:
            print("\n=== Resumen Zeek (conn.log) ===")
            cs = final_report["zeek"]["conn_summary"]
            if "total_connections" in cs:
                print(f"Conexiones: {cs['total_connections']}  |  Servidores únicos: {cs['unique_servers']}  |  Clientes únicos: {cs['unique_clients']}")
                print("Top servicios:", ", ".join([f"{s}:{c}" for s,c in cs["top_services"][:10]]))
            else:
                print(cs.get("note"))
        else:
            print("\n[WARN] Zeek no se ejecutó; sólo se muestran métricas Scapy.")

        if args.keep_temp:
            print(f"[INFO] Directorio temporal conservado en: {tmpdir}")
        else:
            # borrar tmpdir
            shutil.rmtree(tmpdir, ignore_errors=True)

    except Exception as e:
        # intentar limpiar tmpdir salvo que pidamos lo contrario
        if not args.keep_temp:
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except:
                pass
        print("[ERROR] Ocurrió un error:", e)
        raise

if __name__ == "__main__":
    main()
