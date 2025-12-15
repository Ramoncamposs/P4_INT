#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import struct
import re
import shutil
from math import sqrt
from collections import deque
from scapy.all import (
    IP, Raw, sniff, get_if_list,
    IPOption, Packet, PacketListField,
    FieldLenField, IntField, BitField, ShortField,
)
from scapy.layers.inet import _IPOption_HDR

# ======================
# Constantes e formatos
# ======================
MAGIC = b"P4TS"
HDR_FMT = "!4sQI"   # MAGIC(4) + t_send_ns(uint64) + seq(uint32)
HDR_LEN = struct.calcsize(HDR_FMT)

TS48_MASK = (1 << 48) - 1
TS48_WRAP = 1 << 48

S1_ID = 1
S2_ID = 2

# Janela fixa para Flow Bandwidth (segundos)
FLOW_WINDOW_SEC = 1.0

# ======================
# Estruturas do MRI
# ======================
class SwitchTrace(Packet):
    name = "switch_t"
    fields_desc = [
        IntField("swid", 0),
        BitField("ingress_tstamp", 0, 48),
        BitField("egress_tstamp", 0, 48),
    ]
    def extract_padding(self, p):
        return b"", p

class IPOption_MRI(IPOption):
    name, option = "MRI", 31
    fields_desc = [
        _IPOption_HDR,
        FieldLenField("length", None, fmt="B",
                      length_of="swtraces",
                      adjust=lambda pkt, l: (pkt.count * 16) + 4),
        ShortField("count", 0),
        PacketListField("swtraces", [], SwitchTrace,
                        count_from=lambda pkt: pkt.count),
    ]

# ======================
# Estado
# ======================
_last_seq = 0
_recv_count = 0
_lost_total = 0

_last_arrival_time = None          # para Packet Bandwidth (instantâneo)
_last_link_latency_ms = None       # para jitter por pacote (link)

# Acumuladores do desvio-padrão (Welford) para E2E latency
_std_e2e_n = 0
_std_e2e_mean = 0.0
_std_e2e_M2 = 0.0

# janela deslizante p/ Flow Bandwidth
_bw_window = deque()               # tuples (timestamp, bytes)
_bw_bytes = 0                      # bytes acumulados na janela

# ======================
# Utilitários
# ======================
_seq_re = re.compile(r"Packet\s*#(\d+)", re.IGNORECASE)

def find_eth0():
    for name in get_if_list():
        if "eth0" in name:
            return name
    print("Cannot find eth0 interface")
    sys.exit(1)

def parse_payload_header(payload: bytes):
    seq = None
    t_send_ns = None
    if len(payload) >= HDR_LEN and payload[:4] == MAGIC:
        _, t_send_ns, seq = struct.unpack(HDR_FMT, payload[:HDR_LEN])
    else:
        try:
            s = payload.decode(errors="ignore")
            m = _seq_re.search(s)
            if m:
                seq = int(m.group(1))
        except Exception:
            pass
    return seq, t_send_ns

def ts48_signed_diff(a, b):
    d = (int(a) & TS48_MASK) - (int(b) & TS48_MASK)
    d &= TS48_MASK
    if d > (1 << 47):
        d -= TS48_WRAP
    return d

def ts48_sojourn(a_egress, a_ingress):
    return ((int(a_egress) & TS48_MASK) - (int(a_ingress) & TS48_MASK)) & TS48_MASK

def _bw_window_reset():
    global _bw_window, _bw_bytes
    _bw_window.clear()
    _bw_bytes = 0

def _bw_window_add(now_ts, nbytes):
    """Adiciona bytes e remove amostras fora da janela FLOW_WINDOW_SEC."""
    global _bw_window, _bw_bytes
    _bw_window.append((now_ts, nbytes))
    _bw_bytes += nbytes
    cutoff = now_ts - FLOW_WINDOW_SEC
    while _bw_window and _bw_window[0][0] < cutoff:
        t0, b0 = _bw_window.popleft()
        _bw_bytes -= b0
        if _bw_bytes < 0:
            _bw_bytes = 0

def _bw_window_rate_kbps():
    """Taxa média na janela fixa: bytes_em_janela * 8 / FLOW_WINDOW_SEC."""
    if FLOW_WINDOW_SEC <= 0:
        return 0.0
    return (_bw_bytes * 8.0) / FLOW_WINDOW_SEC / 1000.0

# ---------- Layout do bloco enxuto ----------
def _layout_lna():
    cols = shutil.get_terminal_size(fallback=(100, 24)).columns
    lbl_w = max(40, min(64, cols - 28))
    val_w = 10
    return lbl_w, val_w

def print_row(label, value, unit, prec=3):
    LBL_W, VAL_W = _layout_lna()
    fmt_val = f"{value:>{VAL_W}.{prec}f}"
    print(f"  {label:<{LBL_W}}{fmt_val} {unit}")

def print_loss_row(lost, total, ratio):
    LBL_W, VAL_W = _layout_lna()
    perc = f"{ratio*100:>.2f}%"
    txt = f"{lost}/{total} ({perc})"
    print(f"  {'Packet Loss:':<{LBL_W}}{txt:>{VAL_W+6}}")

# ---------- Estatística on-line (Welford) ----------
def welford_update(x):
    """Atualiza n, mean, M2 globais para o desvio-padrão amostral."""
    global _std_e2e_n, _std_e2e_mean, _std_e2e_M2
    _std_e2e_n += 1
    delta = x - _std_e2e_mean
    _std_e2e_mean += delta / _std_e2e_n
    _std_e2e_M2 += delta * (x - _std_e2e_mean)

def welford_std():
    """Retorna desvio-padrão amostral (ms) da E2E latency acumulada."""
    if _std_e2e_n >= 2:
        return sqrt(_std_e2e_M2 / (_std_e2e_n - 1))
    return 0.0

def welford_reset():
    global _std_e2e_n, _std_e2e_mean, _std_e2e_M2
    _std_e2e_n = 0
    _std_e2e_mean = 0.0
    _std_e2e_M2 = 0.0

# ======================
# Handler
# ======================
def handle_pkt(pkt):
    global _last_seq, _recv_count, _lost_total
    global _last_arrival_time, _last_link_latency_ms

    now = time.time()

    if IP not in pkt or Raw not in pkt:
        return

    payload = bytes(pkt[Raw].load)
    seq, _ = parse_payload_header(payload)

    # Reset de métricas ao primeiro pacote da leva
    if seq is not None and seq == 1:
        _last_seq = 0
        _recv_count = 0
        _lost_total = 0
        _last_arrival_time = None
        _last_link_latency_ms = None
        welford_reset()
        _bw_window_reset()

    if IPOption_MRI not in pkt:
        return  # sem MRI não há como calcular

    mri = pkt[IPOption_MRI]

    s1_ing = s1_egr = s2_ing = s2_egr = None
    s1_internal_ms = s2_internal_ms = 0.0

    # Coleta mínima: só o necessário para as métricas
    for t in mri.swtraces:
        sw  = int(t.swid)
        ing = int(t.ingress_tstamp) & TS48_MASK
        egr = int(t.egress_tstamp) & TS48_MASK
        if ing == 0 and egr == 0:
            continue
        soj_ms = ts48_sojourn(egr, ing) / 1e6
        if sw == S1_ID:
            s1_ing, s1_egr = ing, egr
            s1_internal_ms = soj_ms
        elif sw == S2_ID:
            s2_ing, s2_egr = ing, egr
            s2_internal_ms = soj_ms

    if s1_ing is None or s2_egr is None or s2_ing is None:
        return

    # Link (s1->s2)
    link_ms = abs(ts48_signed_diff(s2_ing, s1_egr)) / 1e6

    # Jitter instantâneo (link)
    if _last_link_latency_ms is None:
        jitter_ms = 0.0
    else:
        jitter_ms = abs(link_ms - _last_link_latency_ms)
    _last_link_latency_ms = link_ms

    # End-to-End (somatório robusto)
    e2e_sum_ms = s1_internal_ms + link_ms + s2_internal_ms

    # ---- Atualiza estatística do jitter total (std) sobre a E2E ----
    welford_update(e2e_sum_ms)

    # Perda por sequência
    _recv_count += 1
    if seq is not None and seq > _last_seq + 1:
        _lost_total += (seq - _last_seq - 1)
    if seq is not None:
        _last_seq = max(_last_seq, seq)

    # Vazões
    plen = len(pkt)
    # Packet Bandwidth (instantâneo)
    if _last_arrival_time is None:
        pkt_bw_kbps = 0.0
    else:
        dt = max(1e-6, now - _last_arrival_time)
        pkt_bw_kbps = (plen * 8) / dt / 1000.0
    _last_arrival_time = now

    # Flow Bandwidth (janela deslizante)
    _bw_window_add(now, plen)
    flow_kbps = _bw_window_rate_kbps()

    total_rcv = _lost_total + _recv_count
    loss_ratio = (_lost_total / total_rcv) if total_rcv > 0 else 0.0

    # ---------- Cabeçalho compacto com parâmetros do fluxo ----------
    hhmmss = time.strftime("%H:%M:%S", time.localtime(now))
    seq_txt = f"{seq}" if seq is not None else "?"
    print("\n-------------------------------------------")
    print(f"Got a packet at {now:.2f}s")
    print(f"Sequence Number: {seq_txt}")
    print(f"[{hhmmss}] Recv={_recv_count}/{total_rcv}  Lost={_lost_total}")

    # ---------- Bloco enxuto + latências internas ----------
    print("\n--- Live Network Analysis ---")
    print_row("Link Latency (s1→s2):", link_ms, "ms")
    print_row("Jitter (link, per-packet):", jitter_ms, "ms")
    print_row("Switch s1 Internal Latency:", s1_internal_ms, "ms")
    print_row("Switch s2 Internal Latency:", s2_internal_ms, "ms")
    print_row("End-to-End Latency (s1.ingress→s2.egress):", e2e_sum_ms, "ms")
    print_row("Total Jitter (std, End-to-End):", welford_std(), "ms")
    print_loss_row(_lost_total, total_rcv, loss_ratio)
    print_row("Flow Bandwidth:", flow_kbps, "Kbit/sec", prec=2)
    print_row("Packet Bandwidth:", pkt_bw_kbps, "Kbit/sec", prec=2)
    sys.stdout.flush()

# ======================
# Main
# ======================
def main():
    iface = find_eth0()
    print(f"Sniffing on {iface}... Waiting for packets.")
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface=iface, prn=handle_pkt)

if __name__ == "__main__":
    main()

