#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==========================================================================================
CYBERGUARD SYSTEM AGENT — Interception réseau à l'échelle du système (Windows)
==========================================================================================
Pourquoi cet agent ?
    L'extension Chrome ne protège que Chrome, et seulement si elle est activée. Cet agent
    protège TOUTE la machine (tous navigateurs, toutes applications), même sans extension.

Comment ça marche (2 couches complémentaires) :
    COUCHE 1 — FILTRE DNS (127.0.0.1:53)
        Windows est configuré pour envoyer toutes ses requêtes DNS à l'agent.
        - Domaine bloqué  -> l'agent répond 127.0.0.1 (le trafic est détourné vers la
                             page de blocage locale). Aucune connexion vers le vrai site.
        - Domaine autorisé -> l'agent relaie la requête au DNS d'origine.
        Voit : les NOMS DE DOMAINE (pas les chemins d'URL).
    COUCHE 2 — PROXY SYSTÈME (127.0.0.1:8899)
        Le proxy Windows pointe vers l'agent. Tout le trafic HTTP/HTTPS des applications
        qui respectent le proxy système passe par lui.
        - HTTP  : URL complète analysée (domaine + chemin + paramètres).
        - HTTPS : nom d'hôte analysé via CONNECT (le contenu chiffré n'est PAS déchiffré,
                  aucun certificat n'est installé -> aucune interception TLS invasive).
        Couvre les navigateurs qui utilisent le DNS-over-HTTPS (qui contournent la couche 1).

Décision (identique à l'extension, même cerveau = le backend CyberGuard) :
    - /enterprise/content-filter/inspect : politique MINESEC (adulte, jeux d'argent...)
    - /monitor/realtime-check            : IA (Random Forest + GBM) + heuristiques phishing
    Les paramètres configurés dans la page « Paramètres de Sécurité » s'appliquent ici aussi.

Sécurité & réversibilité :
    - Aucune modification du système n'est faite sans la commande `run` (ou `install`)
      lancée en Administrateur.
    - Les paramètres DNS/proxy d'origine sont sauvegardés (agent/state/network_backup.json)
      et restaurés à l'arrêt normal, par `restore`, ou par restore_network.bat.
    - Par défaut, si le backend est injoignable l'agent LAISSE PASSER (fail-open) pour ne
      jamais couper Internet. Option --fail-closed pour bloquer dans ce cas.

Commandes :
    python cyberguard_agent.py run        # démarre l'agent + configure DNS/proxy (Admin)
    python cyberguard_agent.py run --no-system-config --dns-port 5353   # mode test, sans Admin
    python cyberguard_agent.py restore    # remet DNS/proxy d'origine (Admin)
    python cyberguard_agent.py status     # état de l'agent vu par le backend

Limites honnêtes (à dire au jury) :
    - HTTPS bloqué : sans déchiffrement TLS, le navigateur affiche une erreur de connexion
      (et non la jolie page CyberGuard). La page de blocage s'affiche pour le HTTP, et pour
      HTTPS grâce à l'extension. Déchiffrer le HTTPS exigerait d'installer un certificat
      racine (MITM), volontairement non fait ici.
    - Un utilisateur Administrateur peut désactiver l'agent (comme tout logiciel local).
==========================================================================================
"""
from __future__ import annotations

import argparse
import atexit
import ctypes
import ipaddress
import json
import os
import queue
import select
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(AGENT_DIR, "state")
LOG_DIR = os.path.join(AGENT_DIR, "logs")
BACKUP_FILE = os.path.join(STATE_DIR, "network_backup.json")
EVENTS_LOG = os.path.join(LOG_DIR, "events.jsonl")


# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION (remplie depuis la ligne de commande)
# ──────────────────────────────────────────────────────────────────────────────
class Config:
    backend = "http://localhost:8000/api/v1"
    dns_port = 53
    proxy_port = 8899
    block_http_port = 80          # 0 = désactivé
    sinkhole_ip = "127.0.0.1"
    phishing = True               # analyse IA des hôtes (couche proxy)
    phishing_threshold = 85.0     # score minimal pour bloquer (évite les faux positifs)
    fail_closed = False
    cache_ttl = 60.0
    upstreams: list = ["1.1.1.1", "8.8.8.8"]
    v6_ok = False


CFG = Config()

# Domaines d'infrastructure : jamais soumis à l'IA phishing (évite de casser Windows Update,
# CDN, etc.). La politique de contenu adulte/jeux s'applique TOUJOURS, même à ceux-ci.
TRUSTED_SUFFIXES = (
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com",
    "office365.com", "microsoftonline.com", "azure.com", "azureedge.net", "msftconnecttest.com",
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gvt1.com",
    "cloudflare.com", "cloudfront.net", "amazonaws.com", "akamaiedge.net", "akamaized.net",
    "github.com", "githubusercontent.com", "mozilla.org", "mozilla.com", "apple.com",
    "icloud.com", "whatsapp.com", "whatsapp.net", "facebook.com", "fbcdn.net", "youtube.com",
    "ytimg.com", "wikipedia.org", "cm", "gov.cm", "minesec.gov.cm", "local", "localhost",
)

STATS = {"dns_queries": 0, "dns_blocked": 0, "proxy_requests": 0, "proxy_blocked": 0,
         "allowed": 0, "backend_errors": 0}
STATS_LOCK = threading.Lock()


def bump(key: str, n: int = 1) -> None:
    with STATS_LOCK:
        STATS[key] = STATS.get(key, 0) + n


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ──────────────────────────────────────────────────────────────────────────────
# CLIENT BACKEND (sans passer par le proxy système -> pas de boucle)
# ──────────────────────────────────────────────────────────────────────────────
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(path: str, payload=None, timeout: float = 4.0):
    url = CFG.backend.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"},
        method="POST" if data is not None else "GET")
    with _OPENER.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ──────────────────────────────────────────────────────────────────────────────
# MOTEUR DE DÉCISION (le « garde »)
# ──────────────────────────────────────────────────────────────────────────────
ALLOW = {"block": False}


def normalize_host(host: str) -> str:
    return (host or "").strip().strip("[]").rstrip(".").lower()


def is_local_host(host: str) -> bool:
    """Hôtes qu'on n'analyse jamais : machine locale, réseau privé, noms sans point."""
    if not host or "." not in host:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        pass
    return host.endswith((".local", ".localhost", ".lan", ".internal", ".arpa", ".home.arpa"))


def is_trusted(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in TRUSTED_SUFFIXES)


class Guard:
    def __init__(self) -> None:
        self.cache: dict = {}
        self.lock = threading.Lock()
        self._warned_backend = False

    def decide(self, host: str, url: str | None = None, deep: bool = False) -> dict:
        host = normalize_host(host)
        if is_local_host(host):
            return ALLOW
        key = (url or host) if deep else host
        now = time.time()
        with self.lock:
            hit = self.cache.get(key)
            if hit and hit[0] > now:
                return hit[1]
        verdict = self._evaluate(host, url, deep)
        if verdict.pop("_uncached", False) is False:
            with self.lock:
                if len(self.cache) > 5000:
                    self.cache.clear()
                self.cache[key] = (now + CFG.cache_ttl, verdict)
        return verdict

    def _evaluate(self, host: str, url: str | None, deep: bool) -> dict:
        target = url or f"http://{host}/"
        try:
            # 1) Politique de contenu MINESEC (rapide, toujours appliquée)
            pol = api("/enterprise/content-filter/inspect", {"url": target})
            if pol.get("is_restricted") and pol.get("action") == "BLOCK":
                reasons = pol.get("reasons") or []
                return {"block": True, "kind": "content",
                        "category": pol.get("category", "CONTENU RESTREINT"),
                        "reason": reasons[0] if reasons else "Contenu interdit par la politique MINESEC"}
            # 2) Analyse IA anti-phishing (couche proxy uniquement, hôtes non « infrastructure »)
            if deep and CFG.phishing and not is_trusted(host):
                rt = api("/monitor/realtime-check", {"url": target}, timeout=8.0)
                if not rt.get("is_safe", True) and float(rt.get("risk_score", 0)) >= CFG.phishing_threshold:
                    reasons = rt.get("reasons") or []
                    return {"block": True, "kind": "threat",
                            "category": rt.get("verdict", "MALVEILLANT / PHISHING"),
                            "reason": reasons[0] if reasons else f"Score de risque IA {rt.get('risk_score')}%"}
            return dict(ALLOW)
        except Exception as exc:  # backend injoignable, timeout, JSON invalide...
            bump("backend_errors")
            if not self._warned_backend:
                log(f"ATTENTION backend injoignable ({exc}). Mode "
                    f"{'FAIL-CLOSED (blocage)' if CFG.fail_closed else 'FAIL-OPEN (laisser passer)'}.")
                self._warned_backend = True
            if CFG.fail_closed:
                return {"block": True, "kind": "backend", "category": "BACKEND INDISPONIBLE",
                        "reason": "Analyse impossible, accès refusé par précaution", "_uncached": True}
            return {"block": False, "_uncached": True}


GUARD = Guard()


# ──────────────────────────────────────────────────────────────────────────────
# JOURNAL D'ÉVÉNEMENTS + REMONTÉE VERS LE BACKEND (asynchrone, jamais bloquant)
# ──────────────────────────────────────────────────────────────────────────────
EVENT_QUEUE: "queue.Queue[dict]" = queue.Queue(maxsize=2000)
_recent: dict = {}
STARTED_AT = time.time()


def report_block(via: str, host: str, verdict: dict, url: str | None = None) -> None:
    now = time.time()
    last = _recent.get((via[:3], host))
    if last and now - last < 5:      # une page = 3 requêtes DNS (A/AAAA/HTTPS) -> 1 événement
        return
    _recent[(via[:3], host)] = now
    if len(_recent) > 2000:
        _recent.clear()
    event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "via": via, "host": host, "url": url,
             "category": verdict.get("category"), "reason": verdict.get("reason"),
             "kind": verdict.get("kind"), "action": "BLOCK"}
    log(f"BLOQUÉ [{via}] {host}  ->  {event['category']}")
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(EVENTS_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError:
        pass
    try:
        EVENT_QUEUE.put_nowait(event)
    except queue.Full:
        pass


def reporter_loop(stop: threading.Event) -> None:
    last_beat = 0.0
    while not stop.is_set():
        batch = []
        try:
            while len(batch) < 100:
                batch.append(EVENT_QUEUE.get_nowait())
        except queue.Empty:
            pass
        try:
            if batch:
                api("/enterprise/agent/events", {"events": batch}, timeout=3.0)
            if time.time() - last_beat >= 10:
                with STATS_LOCK:
                    stats = dict(STATS)
                api("/enterprise/agent/heartbeat", {
                    "stats": stats,
                    "info": {"uptime_s": int(time.time() - STARTED_AT), "dns_port": CFG.dns_port,
                             "proxy_port": CFG.proxy_port, "phishing": CFG.phishing,
                             "fail_closed": CFG.fail_closed, "platform": sys.platform}}, timeout=3.0)
                last_beat = time.time()
        except Exception:
            pass
        stop.wait(2.0)


# ──────────────────────────────────────────────────────────────────────────────
# PAGE DE BLOCAGE (autonome : fonctionne même si le frontend est arrêté)
# ──────────────────────────────────────────────────────────────────────────────
def block_page_html(host: str, verdict: dict) -> bytes:
    esc = lambda s: (str(s or "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    html = f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Accès bloqué — CyberGuard</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(ellipse at 50% -10%,#4c0519 0,#090d16 60%);color:#e2e8f0;font-family:Segoe UI,Inter,Arial,sans-serif}}
.card{{max-width:640px;width:92%;text-align:center;padding:40px 32px;border:1px solid #be123c55;border-radius:24px;
background:#0c121fd9;box-shadow:0 25px 60px #e11d4833}}
.ico{{width:84px;height:84px;margin:0 auto 20px;border-radius:24px;background:linear-gradient(135deg,#e11d48,#f59e0b);
display:flex;align-items:center;justify-content:center;font-size:42px}}
.badge{{display:inline-block;padding:6px 14px;border-radius:999px;background:#e11d4833;border:1px solid #e11d4888;
color:#fda4af;font:700 12px monospace;letter-spacing:.12em;text-transform:uppercase}}
h1{{font-size:30px;margin:16px 0 8px}}p{{color:#94a3b8;line-height:1.6;margin:0 0 20px}}
.box{{text-align:left;font-family:Consolas,monospace;font-size:13px;background:#00000066;border:1px solid #1e293b;
border-radius:14px;padding:14px 16px}}.box b{{color:#fda4af}}.k{{color:#64748b;text-transform:uppercase;font-size:11px}}
footer{{margin-top:22px;font-size:11px;color:#475569}}
</style></head><body><div class="card"><div class="ico">&#128737;</div>
<span class="badge">&#9940; Accès interdit — Pare-feu actif</span>
<h1>Ressource bloquée par CyberGuard</h1>
<p>Ce site a été intercepté au niveau du système. L'accès est restreint conformément à la politique de sécurité
de l'établissement (MINESEC).</p>
<div class="box"><div class="k">Domaine</div><b>{esc(host)}</b><br><br>
<div class="k">Catégorie</div>{esc(verdict.get('category'))}<br><br>
<div class="k">Motif</div>{esc(verdict.get('reason'))}</div>
<footer>CyberGuard System Agent — Règle SEC-MINESEC-POL-04 — Code 403</footer></div></body></html>"""
    return html.encode("utf-8")


# ──────────────────────────────────────────────────────────────────────────────
# COUCHE 1 — SERVEUR DNS (UDP + TCP)
# ──────────────────────────────────────────────────────────────────────────────
def dns_parse(data: bytes):
    """Extrait (nom, type, fin_de_question) d'un paquet DNS ; None si invalide."""
    if len(data) < 17:
        return None
    i, labels = 12, []
    while True:
        if i >= len(data):
            return None
        ln = data[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0:
            return None
        labels.append(data[i + 1:i + 1 + ln].decode("ascii", "ignore"))
        i += 1 + ln
    if i + 4 > len(data):
        return None
    qtype = struct.unpack("!H", data[i:i + 2])[0]
    return ".".join(labels), qtype, i + 4


def dns_blocked_response(data: bytes, qtype: int, qend: int) -> bytes:
    """Réponse « sinkhole » : A -> 127.0.0.1 ; AAAA/HTTPS/autres -> NOERROR sans réponse."""
    question = data[12:qend]
    if qtype == 1:
        answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(CFG.sinkhole_ip))
        return data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + answer
    return data[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + question


def dns_servfail(data: bytes) -> bytes:
    qp = dns_parse(data)
    question = data[12:qp[2]] if qp else b""
    return data[:2] + struct.pack("!HHHHH", 0x8182, 1 if qp else 0, 0, 0, 0) + question


def _af(ip: str):
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


def forward_udp(data: bytes):
    for ip in CFG.upstreams:
        try:
            with socket.socket(_af(ip), socket.SOCK_DGRAM) as s:
                s.settimeout(2.5)
                s.sendto(data, (ip, 53))
                resp, _ = s.recvfrom(65535)
                if resp[:2] == data[:2]:
                    return resp
        except OSError:
            continue
    return None


def forward_tcp(data: bytes):
    for ip in CFG.upstreams:
        try:
            with socket.socket(_af(ip), socket.SOCK_STREAM) as s:
                s.settimeout(4.0)
                s.connect((ip, 53))
                s.sendall(struct.pack("!H", len(data)) + data)
                hdr = s.recv(2)
                if len(hdr) < 2:
                    continue
                need = struct.unpack("!H", hdr)[0]
                buf = b""
                while len(buf) < need:
                    chunk = s.recv(need - len(buf))
                    if not chunk:
                        break
                    buf += chunk
                if buf[:2] == data[:2]:
                    return buf
        except OSError:
            continue
    return None


def handle_dns(data: bytes, tcp: bool = False):
    parsed = dns_parse(data)
    forward = forward_tcp if tcp else forward_udp
    if parsed is None:
        return forward(data)
    name, qtype, qend = parsed
    bump("dns_queries")
    host = normalize_host(name)
    if qtype != 12 and host:        # PTR (reverse) jamais filtré
        verdict = GUARD.decide(host)
        if verdict.get("block"):
            bump("dns_blocked")
            report_block("dns", host, verdict)
            return dns_blocked_response(data, qtype, qend)
    resp = forward(data)
    if resp is None and not tcp:
        resp = forward_tcp(data)
    return resp if resp is not None else dns_servfail(data)


class DnsUdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            out = handle_dns(data)
            if out:
                sock.sendto(out, self.client_address)
        except Exception as exc:
            log(f"DNS/UDP erreur: {exc}")


class DnsTcpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5.0)
            while True:
                hdr = self.request.recv(2)
                if len(hdr) < 2:
                    return
                need = struct.unpack("!H", hdr)[0]
                data = b""
                while len(data) < need:
                    chunk = self.request.recv(need - len(data))
                    if not chunk:
                        return
                    data += chunk
                out = handle_dns(data, tcp=True)
                if out:
                    self.request.sendall(struct.pack("!H", len(out)) + out)
        except (OSError, struct.error):
            return


class _UdpServer4(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _UdpServer6(_UdpServer4):
    address_family = socket.AF_INET6


class _TcpServer4(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _TcpServer6(_TcpServer4):
    address_family = socket.AF_INET6


# ──────────────────────────────────────────────────────────────────────────────
# COUCHE 2 — PROXY HTTP/HTTPS
# ──────────────────────────────────────────────────────────────────────────────
class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):  # silence
        pass

    def _blocked(self, host: str, verdict: dict, via: str, url: str | None = None):
        bump("proxy_blocked")
        report_block(via, host, verdict, url)
        body = block_page_html(host, verdict)
        self.send_response(403, "Forbidden")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    # HTTPS : tunnel CONNECT (seul le nom d'hôte est visible, rien n'est déchiffré)
    def do_CONNECT(self):
        bump("proxy_requests")
        host, _, port = self.path.rpartition(":")
        if not host:
            host, port = self.path, "443"
        host = normalize_host(host)
        port = int(port) if port.isdigit() else 443
        verdict = GUARD.decide(host, url=f"https://{host}/", deep=True)
        if verdict.get("block"):
            self._blocked(host, verdict, "proxy-https", f"https://{host}/")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            self.send_error(502, "Bad Gateway")
            return
        bump("allowed")
        self.send_response(200, "Connection Established")
        self.end_headers()
        self._tunnel(upstream)

    def _tunnel(self, upstream: socket.socket):
        client = self.connection
        try:
            while True:
                readable, _, errored = select.select([client, upstream], [], [client, upstream], 120)
                if errored or not readable:
                    break
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        return
                    (upstream if sock is client else client).sendall(data)
        except OSError:
            pass
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    # HTTP : URL complète analysée (domaine + chemin + paramètres)
    def _forward(self):
        bump("proxy_requests")
        url = self.path
        if not url.lower().startswith("http://"):
            self.send_error(400, "CyberGuard proxy: URL absolue requise")
            return
        parts = urlsplit(url)
        host = normalize_host(parts.hostname or "")
        port = parts.port or 80
        verdict = GUARD.decide(host, url=url, deep=True)
        if verdict.get("block"):
            self._blocked(host, verdict, "proxy-http", url)
            return
        body = b""
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            body = self.rfile.read(length)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        skip = {"proxy-connection", "connection", "keep-alive", "proxy-authorization", "te",
                "trailer", "upgrade"}
        lines = [f"{k}: {v}" for k, v in self.headers.items() if k.lower() not in skip]
        request = (f"{self.command} {path} HTTP/1.1\r\n" + "\r\n".join(lines)
                   + "\r\nConnection: close\r\n\r\n").encode("latin-1", "replace") + body
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            self.send_error(502, "Bad Gateway")
            return
        bump("allowed")
        try:
            upstream.sendall(request)
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except OSError:
            pass
        finally:
            upstream.close()
            self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _forward


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


# Serveur de page de blocage (reçoit le trafic détourné par le DNS sinkhole : HTTP uniquement)
class SinkholeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def _page(self):
        host = normalize_host((self.headers.get("Host") or "").split(":")[0]) or "site bloqué"
        verdict = GUARD.decide(host)
        if not verdict.get("block"):
            verdict = {"category": "RESSOURCE RESTREINTE", "reason": "Accès restreint par la politique CyberGuard"}
        else:
            bump("proxy_blocked")
            report_block("sinkhole-http", host, verdict, f"http://{host}{self.path}")
        body = block_page_html(host, verdict)
        self.send_response(403, "Forbidden")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _page


# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION SYSTÈME WINDOWS (DNS + proxy) — sauvegarde & restauration
# ──────────────────────────────────────────────────────────────────────────────
INET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ps(command: str):
    proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-Command", command], capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _as_list(value):
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def capture_dns():
    script = r"""
$r = @()
Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
  $g = $_.InterfaceGuid
  $ns = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$g" -ErrorAction SilentlyContinue).NameServer
  $eff = @((Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4).ServerAddresses)
  $r += [pscustomobject]@{ index = $_.ifIndex; alias = $_.Name; static = [string]$ns; servers = $eff }
}
ConvertTo-Json -InputObject @($r) -Compress -Depth 4
"""
    rc, out, err = ps(script)
    if rc != 0 or not out:
        raise RuntimeError(f"Lecture des cartes réseau impossible: {err}")
    adapters = json.loads(out)
    adapters = adapters if isinstance(adapters, list) else [adapters]
    for a in adapters:
        a["servers"] = _as_list(a.get("servers"))
    return adapters


def read_proxy():
    import winreg
    values = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_KEY, 0, winreg.KEY_READ) as key:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
            try:
                values[name] = winreg.QueryValueEx(key, name)
            except FileNotFoundError:
                values[name] = None
    return values


def _refresh_wininet():
    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)   # SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)   # REFRESH
    except Exception:
        pass


def write_proxy(enable: bool, server: str = "", override: str = "", autoconfig=None):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
        if server:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
        if override:
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, override)
        if autoconfig is not None:
            winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, autoconfig)
        elif enable:
            try:
                winreg.DeleteValue(key, "AutoConfigURL")
            except FileNotFoundError:
                pass
    _refresh_wininet()


def network_apply():
    if sys.platform != "win32":
        raise RuntimeError("La configuration système automatique n'est disponible que sous Windows.")
    if not is_admin():
        raise PermissionError("Lancez cette commande dans un terminal ADMINISTRATEUR.")
    os.makedirs(STATE_DIR, exist_ok=True)

    if os.path.exists(BACKUP_FILE):
        log("Sauvegarde réseau existante conservée (exécution précédente non restaurée).")
        with open(BACKUP_FILE, encoding="utf-8") as fh:
            backup = json.load(fh)
    else:
        backup = {"dns": capture_dns(), "proxy": {k: v for k, v in read_proxy().items()}, "saved_at": time.ctime()}
        with open(BACKUP_FILE, "w", encoding="utf-8") as fh:
            json.dump(backup, fh, indent=2)
        log(f"Paramètres d'origine sauvegardés -> {BACKUP_FILE}")

    # DNS d'origine réutilisés comme « upstream » (VPN / DNS d'entreprise respectés)
    originals = []
    for adapter in backup["dns"]:
        for s in adapter["servers"]:
            if s not in ("127.0.0.1", "::1") and s not in originals:
                originals.append(s)
    CFG.upstreams = originals + [u for u in ("1.1.1.1", "8.8.8.8") if u not in originals]
    log(f"DNS amont (relais) : {', '.join(CFG.upstreams)}")

    addrs = "'127.0.0.1','::1'" if CFG.v6_ok else "'127.0.0.1'"
    for adapter in backup["dns"]:
        rc, _, err = ps(f"Set-DnsClientServerAddress -InterfaceIndex {adapter['index']} -ServerAddresses @({addrs})")
        log(f"DNS -> 127.0.0.1 sur « {adapter['alias']} » : {'OK' if rc == 0 else 'ECHEC ' + err}")
    ps("ipconfig /flushdns | Out-Null")

    write_proxy(True, f"127.0.0.1:{CFG.proxy_port}", "localhost;127.*;10.*;192.168.*;<local>")
    log(f"Proxy système -> 127.0.0.1:{CFG.proxy_port}")


_restored = False


def network_restore():
    global _restored
    if _restored or sys.platform != "win32":
        return
    if not os.path.exists(BACKUP_FILE):
        log("Aucune sauvegarde réseau : rien à restaurer.")
        return
    _restored = True
    with open(BACKUP_FILE, encoding="utf-8") as fh:
        backup = json.load(fh)
    log("Restauration des paramètres réseau d'origine...")
    for adapter in backup["dns"]:
        if adapter.get("static"):
            servers = ",".join(f"'{s}'" for s in adapter["servers"] if s not in ("127.0.0.1", "::1"))
            cmd = (f"Set-DnsClientServerAddress -InterfaceIndex {adapter['index']} -ServerAddresses @({servers})"
                   if servers else f"Set-DnsClientServerAddress -InterfaceIndex {adapter['index']} -ResetServerAddresses")
        else:
            cmd = f"Set-DnsClientServerAddress -InterfaceIndex {adapter['index']} -ResetServerAddresses"
        rc, _, err = ps(cmd)
        log(f"DNS « {adapter['alias']} » restauré : {'OK' if rc == 0 else 'ECHEC ' + err}")
    ps("ipconfig /flushdns | Out-Null")

    proxy = backup.get("proxy", {})
    enable = (proxy.get("ProxyEnable") or [0])[0]
    write_proxy(bool(enable), (proxy.get("ProxyServer") or [""])[0] or "",
                (proxy.get("ProxyOverride") or [""])[0] or "")
    if proxy.get("AutoConfigURL"):
        write_proxy(bool(enable), autoconfig=proxy["AutoConfigURL"][0])
    if not enable:
        write_proxy(False)
    try:
        os.remove(BACKUP_FILE)
    except OSError:
        pass
    log("Réseau restauré.")


# ──────────────────────────────────────────────────────────────────────────────
# DÉMARRAGE
# ──────────────────────────────────────────────────────────────────────────────
def start_servers(stop: threading.Event):
    started = []

    def serve(server, name):
        threading.Thread(target=server.serve_forever, name=name, daemon=True).start()
        started.append(server)

    # DNS IPv4 (obligatoire) — UDP + TCP
    serve(_UdpServer4(("127.0.0.1", CFG.dns_port), DnsUdpHandler), "dns-udp4")
    serve(_TcpServer4(("127.0.0.1", CFG.dns_port), DnsTcpHandler), "dns-tcp4")
    log(f"Filtre DNS à l'écoute sur 127.0.0.1:{CFG.dns_port} (UDP+TCP)")
    # DNS IPv6 (best effort)
    try:
        serve(_UdpServer6(("::1", CFG.dns_port), DnsUdpHandler), "dns-udp6")
        serve(_TcpServer6(("::1", CFG.dns_port), DnsTcpHandler), "dns-tcp6")
        CFG.v6_ok = True
        log(f"Filtre DNS à l'écoute sur [::1]:{CFG.dns_port}")
    except OSError:
        log("IPv6 (::1) indisponible : DNS IPv4 uniquement.")

    serve(ProxyServer(("127.0.0.1", CFG.proxy_port), ProxyHandler), "proxy")
    log(f"Proxy HTTP/HTTPS à l'écoute sur 127.0.0.1:{CFG.proxy_port}")

    if CFG.block_http_port:
        try:
            serve(ThreadingHTTPServer(("127.0.0.1", CFG.block_http_port), SinkholeHandler), "blockpage")
            log(f"Page de blocage locale sur 127.0.0.1:{CFG.block_http_port}")
        except OSError as exc:
            log(f"Page de blocage port {CFG.block_http_port} indisponible ({exc}) — le proxy reste actif.")

    threading.Thread(target=reporter_loop, args=(stop,), name="reporter", daemon=True).start()
    return started


def install_shutdown_hooks(stop: threading.Event):
    def _shutdown(*_):
        stop.set()
    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    if sys.platform == "win32":
        try:
            HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)

            def console_handler(event):
                if event in (2, 5, 6):          # fermeture fenêtre / déconnexion / arrêt
                    network_restore()
                    stop.set()
                    return True
                return False

            global _console_handler_ref
            _console_handler_ref = HandlerRoutine(console_handler)
            ctypes.windll.kernel32.SetConsoleCtrlHandler(_console_handler_ref, True)
        except Exception:
            pass


def cmd_run(args) -> int:
    CFG.backend = args.backend
    CFG.dns_port = args.dns_port
    CFG.proxy_port = args.proxy_port
    CFG.block_http_port = args.block_http_port
    CFG.phishing = not args.no_phishing
    CFG.phishing_threshold = args.phishing_threshold
    CFG.fail_closed = args.fail_closed
    if args.upstream:
        CFG.upstreams = args.upstream

    system = not args.no_system_config
    if system and (sys.platform != "win32" or not is_admin()):
        print("ERREUR: la configuration système exige Windows + un terminal ADMINISTRATEUR.\n"
              "        (Ou utilisez --no-system-config pour tester sans toucher au système.)")
        return 2

    stop = threading.Event()
    try:
        start_servers(stop)
    except OSError as exc:
        print(f"ERREUR: impossible d'ouvrir un port ({exc}). Un autre programme utilise-t-il le port 53 ?")
        return 3
    install_shutdown_hooks(stop)

    if system:
        atexit.register(network_restore)
        try:
            network_apply()
        except Exception as exc:
            print(f"ERREUR configuration système: {exc}")
            network_restore()
            return 4
        log("PROTECTION SYSTÈME ACTIVE — tout le trafic de la machine est analysé. Ctrl+C pour arrêter.")
    else:
        log("Mode TEST (--no-system-config) : le système n'est PAS modifié.")

    try:
        while not stop.is_set():
            stop.wait(0.5)
    finally:
        if system:
            network_restore()
        log("Agent arrêté.")
    return 0


def cmd_restore(_args) -> int:
    if not is_admin():
        print("ERREUR: terminal ADMINISTRATEUR requis.")
        return 2
    network_restore()
    return 0


def cmd_status(args) -> int:
    CFG.backend = args.backend
    try:
        print(json.dumps(api("/enterprise/agent/status"), indent=2, ensure_ascii=False))
    except Exception as exc:
        print(f"Backend injoignable: {exc}")
    print("Sauvegarde réseau présente (agent actif ou arrêt anormal) :", os.path.exists(BACKUP_FILE))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="CyberGuard System Agent (DNS + proxy système)")
    sub = parser.add_subparsers(dest="cmd")
    run = sub.add_parser("run", help="Démarre l'agent")
    run.add_argument("--backend", default=Config.backend)
    run.add_argument("--dns-port", type=int, default=53)
    run.add_argument("--proxy-port", type=int, default=8899)
    run.add_argument("--block-http-port", type=int, default=80, help="0 pour désactiver")
    run.add_argument("--upstream", action="append", help="DNS amont (répétable)")
    run.add_argument("--no-phishing", action="store_true", help="Désactive l'analyse IA (contenu MINESEC seul)")
    run.add_argument("--phishing-threshold", type=float, default=85.0)
    run.add_argument("--fail-closed", action="store_true", help="Bloquer si le backend est injoignable")
    run.add_argument("--no-system-config", action="store_true", help="Mode test : ne modifie ni DNS ni proxy")
    sub.add_parser("restore", help="Restaure DNS/proxy d'origine")
    st = sub.add_parser("status", help="État vu par le backend")
    st.add_argument("--backend", default=Config.backend)

    args = parser.parse_args()
    if args.cmd in (None, "run"):
        if args.cmd is None:
            args = run.parse_args([])
        return cmd_run(args)
    if args.cmd == "restore":
        return cmd_restore(args)
    return cmd_status(args)


if __name__ == "__main__":
    sys.exit(main())
