from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import asyncio
from emergentintegrations.llm.chat import LlmChat, UserMessage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# LLM API Key
EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY', '')

# Create the main app
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Known RAT signatures database
RAT_SIGNATURES = [
    {"name": "DarkComet", "processes": ["darkcomet.exe", "dc.exe"], "ports": [1604, 1605]},
    {"name": "njRAT", "processes": ["njrat.exe", "server.exe"], "ports": [5552, 1177]},
    {"name": "Poison Ivy", "processes": ["pi.exe", "poison.exe"], "ports": [3460, 65535]},
    {"name": "Xtreme RAT", "processes": ["xrat.exe", "xtreme.exe"], "ports": [7896, 7897]},
    {"name": "NetWire", "processes": ["netwire.exe", "host.exe"], "ports": [3360, 3361]},
    {"name": "Remcos", "processes": ["remcos.exe", "rmc.exe"], "ports": [2404, 2405]},
    {"name": "AsyncRAT", "processes": ["asyncrat.exe", "stub.exe"], "ports": [6606, 7707]},
    {"name": "QuasarRAT", "processes": ["quasar.exe", "client.exe"], "ports": [4782, 4783]},
    {"name": "Cobalt Strike", "processes": ["beacon.exe", "artifact.exe"], "ports": [50050, 443]},
    {"name": "Meterpreter", "processes": ["metsvc.exe", "met.exe"], "ports": [4444, 4445]},
]

SUSPICIOUS_PORTS = [4444, 4445, 5552, 1177, 3460, 65535, 7896, 50050, 6666, 31337, 12345, 1337]

# Models
class Detection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_type: str  # "rat_signature", "suspicious_port", "suspicious_connection"
    threat_name: str
    severity: str  # "critical", "high", "medium", "low"
    details: dict
    ai_analysis: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "active"  # "active", "resolved", "false_positive"

class ScanResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_type: str  # "full", "quick", "network"
    total_items_scanned: int
    threats_found: int
    detections: List[str] = []  # Detection IDs
    duration_seconds: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SystemStatus(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cpu_usage: float
    memory_usage: float
    active_connections: int
    suspicious_connections: int
    last_scan: Optional[datetime] = None
    threat_level: str = "safe"  # "safe", "warning", "danger"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class NetworkConnection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    local_address: str
    remote_address: str
    remote_port: int
    protocol: str
    status: str
    process_name: Optional[str] = None
    is_suspicious: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AIAnalysisRequest(BaseModel):
    detection_id: str
    threat_data: dict

class ScanRequest(BaseModel):
    scan_type: str = "full"

# AI Analysis function
async def analyze_threat_with_ai(threat_data: dict) -> str:
    """Use AI to analyze a potential threat"""
    if not EMERGENT_LLM_KEY:
        return "AI analysis unavailable - API key not configured"
    
    try:
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=f"threat-analysis-{uuid.uuid4()}",
            system_message="""You are a cybersecurity expert specializing in RAT (Remote Access Trojan) detection and malware analysis. 
            Analyze the provided threat data and give a concise assessment including:
            1. Threat severity (Critical/High/Medium/Low)
            2. What this threat could do
            3. Recommended immediate actions
            Keep response under 150 words and be specific."""
        ).with_model("openai", "gpt-4o")
        
        user_message = UserMessage(
            text=f"Analyze this potential security threat:\n{str(threat_data)}"
        )
        
        response = await chat.send_message(user_message)
        return response
    except Exception as e:
        logging.error(f"AI analysis error: {e}")
        return f"AI analysis failed: {str(e)}"

# Simulated scan function (in production, this would scan actual system)
async def perform_system_scan(scan_type: str) -> dict:
    """Simulate a system scan for RATs"""
    import random
    
    detections = []
    items_scanned = random.randint(1000, 5000) if scan_type == "full" else random.randint(100, 500)
    
    # Simulate finding threats (for demo purposes)
    if random.random() < 0.3:  # 30% chance to find something
        rat = random.choice(RAT_SIGNATURES)
        detection = {
            "detection_type": "rat_signature",
            "threat_name": rat["name"],
            "severity": random.choice(["critical", "high"]),
            "details": {
                "matched_process": random.choice(rat["processes"]),
                "matched_port": random.choice(rat["ports"]),
                "location": f"C:\\Users\\User\\AppData\\Local\\Temp\\{random.choice(rat['processes'])}",
                "md5_hash": uuid.uuid4().hex[:32]
            }
        }
        detections.append(detection)
    
    # Check for suspicious network connections
    if random.random() < 0.4:  # 40% chance
        suspicious_port = random.choice(SUSPICIOUS_PORTS)
        detection = {
            "detection_type": "suspicious_connection",
            "threat_name": f"Suspicious Outbound Port {suspicious_port}",
            "severity": "medium",
            "details": {
                "remote_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "remote_port": suspicious_port,
                "protocol": "TCP",
                "process": "svchost.exe"
            }
        }
        detections.append(detection)
    
    return {
        "items_scanned": items_scanned,
        "detections": detections
    }

# Routes
@api_router.get("/")
async def root():
    return {"message": "RAT Detection API v1.0"}

@api_router.get("/status")
async def get_system_status():
    """Get current system security status"""
    import random
    
    # Get detection counts
    active_threats = await db.detections.count_documents({"status": "active"})
    total_detections = await db.detections.count_documents({})
    
    # Get last scan
    last_scan = await db.scans.find_one({}, {"_id": 0}, sort=[("timestamp", -1)])
    
    threat_level = "safe"
    if active_threats > 0:
        threat_level = "danger" if active_threats > 2 else "warning"
    
    return {
        "cpu_usage": round(random.uniform(15, 45), 1),
        "memory_usage": round(random.uniform(40, 70), 1),
        "active_connections": random.randint(20, 80),
        "suspicious_connections": active_threats,
        "total_detections": total_detections,
        "active_threats": active_threats,
        "last_scan": last_scan["timestamp"] if last_scan else None,
        "threat_level": threat_level,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@api_router.post("/scan")
async def start_scan(request: ScanRequest):
    """Start a system scan"""
    start_time = datetime.now(timezone.utc)
    
    # Perform scan
    scan_results = await perform_system_scan(request.scan_type)
    
    # Store detections
    detection_ids = []
    for det in scan_results["detections"]:
        detection = Detection(**det)
        doc = detection.model_dump()
        doc['timestamp'] = doc['timestamp'].isoformat()
        await db.detections.insert_one(doc)
        detection_ids.append(detection.id)
    
    # Calculate duration
    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()
    
    # Store scan result
    scan_result = ScanResult(
        scan_type=request.scan_type,
        total_items_scanned=scan_results["items_scanned"],
        threats_found=len(scan_results["detections"]),
        detections=detection_ids,
        duration_seconds=duration
    )
    
    doc = scan_result.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.scans.insert_one(doc)
    
    return {
        "id": scan_result.id,
        "scan_type": scan_result.scan_type,
        "items_scanned": scan_result.total_items_scanned,
        "threats_found": scan_result.threats_found,
        "duration": duration,
        "detections": scan_results["detections"]
    }

@api_router.get("/detections")
async def get_detections(status: Optional[str] = None, limit: int = 50):
    """Get all detections"""
    query = {}
    if status:
        query["status"] = status
    
    detections = await db.detections.find(query, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    
    for det in detections:
        if isinstance(det.get('timestamp'), str):
            det['timestamp'] = datetime.fromisoformat(det['timestamp'])
    
    return detections

@api_router.get("/detections/{detection_id}")
async def get_detection(detection_id: str):
    """Get a specific detection"""
    detection = await db.detections.find_one({"id": detection_id}, {"_id": 0})
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    return detection

@api_router.post("/detections/{detection_id}/analyze")
async def analyze_detection(detection_id: str):
    """Run AI analysis on a detection"""
    detection = await db.detections.find_one({"id": detection_id}, {"_id": 0})
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    
    # Run AI analysis
    ai_analysis = await analyze_threat_with_ai(detection)
    
    # Update detection with analysis
    await db.detections.update_one(
        {"id": detection_id},
        {"$set": {"ai_analysis": ai_analysis}}
    )
    
    return {"detection_id": detection_id, "ai_analysis": ai_analysis}

@api_router.patch("/detections/{detection_id}/status")
async def update_detection_status(detection_id: str, status: str):
    """Update detection status"""
    if status not in ["active", "resolved", "false_positive"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    result = await db.detections.update_one(
        {"id": detection_id},
        {"$set": {"status": status}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Detection not found")
    
    return {"message": "Status updated", "detection_id": detection_id, "status": status}

@api_router.get("/scans")
async def get_scan_history(limit: int = 20):
    """Get scan history"""
    scans = await db.scans.find({}, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    return scans

@api_router.get("/network/connections")
async def get_network_connections():
    """Get simulated network connections"""
    import random
    
    connections = []
    for _ in range(random.randint(10, 25)):
        is_suspicious = random.random() < 0.15
        port = random.choice(SUSPICIOUS_PORTS) if is_suspicious else random.choice([80, 443, 8080, 3306, 5432])
        
        conn = {
            "id": str(uuid.uuid4()),
            "local_address": f"192.168.1.{random.randint(1, 254)}",
            "remote_address": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "remote_port": port,
            "protocol": random.choice(["TCP", "UDP"]),
            "status": random.choice(["ESTABLISHED", "LISTEN", "TIME_WAIT"]),
            "process_name": random.choice(["chrome.exe", "firefox.exe", "svchost.exe", "explorer.exe", "unknown.exe"]),
            "is_suspicious": is_suspicious,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        connections.append(conn)
    
    return connections

@api_router.get("/signatures")
async def get_rat_signatures():
    """Get known RAT signatures database"""
    return RAT_SIGNATURES

@api_router.get("/stats")
async def get_statistics():
    """Get detection statistics"""
    total_scans = await db.scans.count_documents({})
    total_detections = await db.detections.count_documents({})
    active_threats = await db.detections.count_documents({"status": "active"})
    resolved_threats = await db.detections.count_documents({"status": "resolved"})
    false_positives = await db.detections.count_documents({"status": "false_positive"})
    
    # Get detections by type
    pipeline = [
        {"$group": {"_id": "$detection_type", "count": {"$sum": 1}}}
    ]
    by_type = await db.detections.aggregate(pipeline).to_list(100)
    
    # Get detections by severity
    severity_pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ]
    by_severity = await db.detections.aggregate(severity_pipeline).to_list(100)
    
    return {
        "total_scans": total_scans,
        "total_detections": total_detections,
        "active_threats": active_threats,
        "resolved_threats": resolved_threats,
        "false_positives": false_positives,
        "by_type": {item["_id"]: item["count"] for item in by_type if item["_id"]},
        "by_severity": {item["_id"]: item["count"] for item in by_severity if item["_id"]}
    }

# Include the router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
