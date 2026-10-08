import time
from collections import deque
from typing import Optional, List, Any, Dict
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

# ── 5. CONTENT FILTER & MINESEC SCHOOL PROTECTION POLICY ─────────────
from app.services.content_filter_service import (
    load_policy_settings, save_policy_settings, check_url_content_policy
)

class PolicySettingsUpdate(BaseModel):
    block_adult_content: Optional[bool] = None
    block_gambling: Optional[bool] = None
    enforcement_mode: Optional[str] = None  # "BLOCK" | "WARN" | "ALLOW"
    school_shield_active: Optional[bool] = None
    redirect_to_block_page: Optional[bool] = None
    custom_blacklist: Optional[list] = None
    custom_whitelist: Optional[list] = None

class ContentFilterTestRequest(BaseModel):
    url: str

@router.get("/policy-settings")
def get_policy_settings():
    """Retrieve current content filtering and school shield policy settings."""
    return load_policy_settings()

@router.post("/policy-settings")
def update_policy_settings(req: PolicySettingsUpdate):
    """Update content filtering policies (adult content, gambling, enforcement mode)."""
    current = load_policy_settings()
    if req.block_adult_content is not None:
        current["block_adult_content"] = req.block_adult_content
    if req.block_gambling is not None:
        current["block_gambling"] = req.block_gambling
    if req.enforcement_mode is not None:
        current["enforcement_mode"] = req.enforcement_mode.upper()
    if req.school_shield_active is not None:
        current["school_shield_active"] = req.school_shield_active
    if req.redirect_to_block_page is not None:
        current["redirect_to_block_page"] = req.redirect_to_block_page
    if req.custom_blacklist is not None:
        current["custom_blacklist"] = req.custom_blacklist
    if req.custom_whitelist is not None:
        current["custom_whitelist"] = req.custom_whitelist

    success = save_policy_settings(current)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save policy settings")
    return {"status": "updated", "settings": current}

@router.post("/content-filter/inspect")
def inspect_url_content_policy(req: ContentFilterTestRequest):
    """Inspect an URL against active adult content and gambling protection policies."""
    if not req.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    return check_url_content_policy(req.url)


# ── SYSTEM-WIDE AGENT (DNS + proxy) : état en mémoire ────────────────────
AGENT_STATE: Dict[str, Any] = {"last_seen": 0.0, "stats": {}, "info": {}}
AGENT_EVENTS: deque = deque(maxlen=500)

class AgentHeartbeat(BaseModel):
    stats: Dict[str, Any] = {}
    info: Dict[str, Any] = {}

class AgentEvents(BaseModel):
    events: List[Dict[str, Any]] = []

@router.post("/agent/heartbeat")
def agent_heartbeat(req: AgentHeartbeat):
    """Le agent système signale qu'il est vivant et envoie ses compteurs."""
    AGENT_STATE.update(last_seen=time.time(), stats=req.stats, info=req.info)
    return {"ok": True}

@router.post("/agent/events")
def agent_events(req: AgentEvents):
    """Réception des blocages interceptés par le agent (DNS / proxy)."""
    for ev in req.events:
        AGENT_EVENTS.appendleft(ev)
    return {"ok": True, "received": len(req.events)}

@router.get("/agent/status")
def agent_status():
    age = time.time() - AGENT_STATE["last_seen"] if AGENT_STATE["last_seen"] else None
    return {
        "online": age is not None and age < 30,
        "last_seen_seconds": round(age, 1) if age is not None else None,
        "stats": AGENT_STATE["stats"],
        "info": AGENT_STATE["info"],
        "total_events": len(AGENT_EVENTS),
    }

@router.get("/agent/events")
def agent_events_list(limit: int = 50):
    return {"events": list(AGENT_EVENTS)[:max(1, min(limit, 500))]}

