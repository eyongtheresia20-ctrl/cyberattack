from typing import Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends
from pydantic import BaseModel

from app.services.sandbox_service import analyze_url_sandbox
from app.services.pcap_analyzer import analyze_pcap_data
from app.services.firewall_service import (
    list_all_blocked_ips, block_ip_address, unblock_ip_address,
    record_honeypot_hit, get_honeypot_hits
)
from app.api.v1.auth import get_optional_user

router = APIRouter(prefix="/enterprise", tags=["Enterprise Advanced Defense Modules"])

class SandboxRequest(BaseModel):
    url: str

class BlockIpRequest(BaseModel):
    ip: str
    reason: Optional[str] = "Activité hostile interceptée"
    severity: Optional[str] = "HIGH"

class UnblockIpRequest(BaseModel):
    ip: str

class PcapScenarioRequest(BaseModel):
    scenario: str = "SYN_FLOOD" # "SYN_FLOOD", "PORT_SCAN", "DNS_TUNNEL"

class HoneypotSimulateRequest(BaseModel):
    trap: str = "/wp-login.php"
    ip: str = "194.26.29.112"
    payload: str = "Probe bot attempt"

# ── 1. HEADLESS SANDBOX & LIVE DOM INSPECTION ─────────────────────────
@router.post("/sandbox")
def run_url_sandbox(req: SandboxRequest):
    """Detonate and analyze a target URL in the headless browser sandbox."""
    if not req.url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")
    return analyze_url_sandbox(req.url)

# ── 2. PCAP & LAYER 3/4 PACKET ANALYZER ──────────────────────────────
@router.post("/pcap/scenario")
def analyze_pcap_scenario(req: PcapScenarioRequest):
    """Analyze a predefined enterprise Layer 3/4 network attack scenario."""
    return analyze_pcap_data(scenario=req.scenario)

@router.post("/pcap/upload")
async def upload_pcap_file(file: UploadFile = File(...)):
    """Upload and inspect a live .pcap or .pcapng network capture file."""
    content = await file.read()
    return analyze_pcap_data(filename=file.filename, raw_bytes=content)

# ── 3. ACTIVE INLINE FIREWALL & WAF IP BANNING ────────────────────────
@router.get("/firewall/blocked-ips")
def get_blocked_ips():
    """List all currently banned attacker IPs in the active WAF firewall."""
    return {"blocked_ips": list_all_blocked_ips()}

@router.post("/firewall/block")
def block_ip(req: BlockIpRequest):
    """Actively block an attacker IP in the inline WAF firewall."""
    entry = block_ip_address(ip=req.ip, reason=req.reason, severity=req.severity)
    return {"status": "blocked", "entry": entry}

@router.post("/firewall/unblock")
def unblock_ip(req: UnblockIpRequest):
    """Remove an IP address from the firewall blacklist."""
    success = unblock_ip_address(req.ip)
    return {"status": "unblocked" if success else "not_found", "ip": req.ip}

# ── 4. HONEYPOT TRAP & BOT DECOY MONITOR ──────────────────────────────
@router.get("/honeypot/traps")
def get_honeypot_events():
    """Retrieve all attackers caught by CyberGuard honeypot decoy traps."""
    return {"hits": get_honeypot_hits()}

@router.post("/honeypot/simulate")
def simulate_honeypot_probe(req: HoneypotSimulateRequest):
    """Simulate a reconnaissance bot hitting a honeypot trap."""
    hit = record_honeypot_hit(
        trap_endpoint=req.trap,
        attacker_ip=req.ip,
        user_agent="Mozilla/5.0 (Automated Recon Bot)",
        payload=req.payload
    )
    return {"status": "trapped_and_banned", "event": hit}
