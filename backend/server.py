from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import asyncio
import hashlib
import random
from emergentintegrations.llm.chat import LlmChat, UserMessage

# Import Entropy Engine for Phi-Pi-Entropy based countermeasures
from entropy_engine import (
    entropy_engine, 
    anomaly_detector, 
    entropic_neutralizer,
    EntropyEngine,
    GraphAnomalyDetector,
    EntropicNeutralizer
)

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
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============== RAT DATABASE ==============
RAT_SIGNATURES = [
    {"name": "DarkComet", "processes": ["darkcomet.exe", "dc.exe"], "ports": [1604, 1605], "behaviors": ["keylogging", "screen_capture", "file_transfer"]},
    {"name": "njRAT", "processes": ["njrat.exe", "server.exe"], "ports": [5552, 1177], "behaviors": ["keylogging", "webcam_access", "persistence"]},
    {"name": "Poison Ivy", "processes": ["pi.exe", "poison.exe"], "ports": [3460, 65535], "behaviors": ["rootkit", "file_transfer", "shell_access"]},
    {"name": "Xtreme RAT", "processes": ["xrat.exe", "xtreme.exe"], "ports": [7896, 7897], "behaviors": ["ddos", "keylogging", "password_theft"]},
    {"name": "NetWire", "processes": ["netwire.exe", "host.exe"], "ports": [3360, 3361], "behaviors": ["keylogging", "browser_theft", "persistence"]},
    {"name": "Remcos", "processes": ["remcos.exe", "rmc.exe"], "ports": [2404, 2405], "behaviors": ["surveillance", "keylogging", "shell_access"]},
    {"name": "AsyncRAT", "processes": ["asyncrat.exe", "stub.exe"], "ports": [6606, 7707], "behaviors": ["crypto_mining", "ransomware", "data_exfil"]},
    {"name": "QuasarRAT", "processes": ["quasar.exe", "client.exe"], "ports": [4782, 4783], "behaviors": ["file_manager", "remote_desktop", "keylogging"]},
    {"name": "Cobalt Strike", "processes": ["beacon.exe", "artifact.exe"], "ports": [50050, 443], "behaviors": ["lateral_movement", "privilege_escalation", "c2_comms"]},
    {"name": "Meterpreter", "processes": ["metsvc.exe", "met.exe"], "ports": [4444, 4445], "behaviors": ["shell_access", "file_transfer", "pivoting"]},
]

SUSPICIOUS_PORTS = [4444, 4445, 5552, 1177, 3460, 65535, 7896, 50050, 6666, 31337, 12345, 1337]

# ============== COUNTERMEASURE TECHNIQUES ==============
COUNTERMEASURE_TECHNIQUES = {
    "fault_injection": {
        "name": "Fault Injection",
        "description": "Introduce controlled errors to disrupt RAT process execution",
        "risk_level": "low",
        "effectiveness": 0.7
    },
    "resource_starvation": {
        "name": "Resource Starvation",
        "description": "Limit CPU/memory allocation to suspected RAT processes",
        "risk_level": "low",
        "effectiveness": 0.6
    },
    "network_isolation": {
        "name": "Network Isolation",
        "description": "Block suspicious outbound connections to C2 servers",
        "risk_level": "medium",
        "effectiveness": 0.85
    },
    "process_termination": {
        "name": "Process Termination",
        "description": "Forcefully terminate identified RAT processes",
        "risk_level": "medium",
        "effectiveness": 0.9
    },
    "memory_corruption": {
        "name": "Memory Corruption",
        "description": "Corrupt RAT process memory to cause crashes",
        "risk_level": "low",
        "effectiveness": 0.75
    },
    "decoy_deployment": {
        "name": "Decoy Deployment",
        "description": "Deploy honeypot files/processes to confuse RATs",
        "risk_level": "none",
        "effectiveness": 0.5
    },
    "entropic_flood_poetic": {
        "name": "Entropic Flood (Poetic)",
        "description": "Phi-Pi-Entropy chaos flood with conjugate inversion for entropy cancellation",
        "risk_level": "none",
        "effectiveness": 0.88
    },
    "entropic_flood_brute": {
        "name": "Entropic Flood (Brute)",
        "description": "Triple chaos assault with entropy overwhelming - maximum disruption",
        "risk_level": "low",
        "effectiveness": 0.92
    }
}

# ============== MODELS ==============
class Detection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_type: str
    threat_name: str
    severity: str
    details: dict
    signature_hash: Optional[str] = None
    behavioral_profile: Optional[List[str]] = None
    mutation_detected: bool = False
    parent_threat_id: Optional[str] = None
    ai_analysis: Optional[str] = None
    entropy_score: Optional[float] = None
    entropy_profile: Optional[dict] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "active"

class Countermeasure(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_id: str
    technique: str
    action_taken: str
    success: bool
    ai_reasoning: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class WarLogEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str  # "detection", "countermeasure", "mutation", "eviction", "escalation", "learning"
    threat_id: Optional[str] = None
    threat_name: Optional[str] = None
    description: str
    ai_decision: Optional[str] = None
    outcome: Optional[str] = None
    tactics_learned: Optional[List[str]] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AgentState(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = "agent_state_singleton"
    is_active: bool = True
    mode: str = "autonomous"  # autonomous, defensive, aggressive
    threats_evicted: int = 0
    threats_active: int = 0
    mutations_detected: int = 0
    countermeasures_deployed: int = 0
    learning_iterations: int = 0
    last_action: Optional[str] = None
    last_action_time: Optional[datetime] = None

class ThreatIntelligence(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    threat_name: str
    known_behaviors: List[str]
    effective_countermeasures: List[str]
    mutation_patterns: List[str]
    evasion_tactics: List[str]
    weakness_discovered: Optional[str] = None

# ============== AI AGENT CORE ==============
class RATCountermeasureAgent:
    def __init__(self):
        self.session_id = str(uuid.uuid4())
        self.tactics_memory = []
        
    async def analyze_threat(self, threat_data: dict) -> dict:
        """AI analyzes threat and decides countermeasure strategy"""
        if not EMERGENT_LLM_KEY:
            return {"strategy": "process_termination", "reasoning": "Default strategy - AI unavailable"}
        
        try:
            chat = LlmChat(
                api_key=EMERGENT_LLM_KEY,
                session_id=f"agent-{self.session_id}",
                system_message="""You are an autonomous cybersecurity AI agent specialized in RAT (Remote Access Trojan) countermeasures.
                
Your mission: Evict threats using non-harmful techniques. Analyze the threat and decide the best countermeasure strategy.

Available techniques:
1. fault_injection - Introduce errors to crash RAT
2. resource_starvation - Starve RAT of CPU/memory
3. network_isolation - Block C2 communications
4. process_termination - Kill RAT process
5. memory_corruption - Corrupt RAT memory space
6. decoy_deployment - Deploy honeypots to confuse

Consider:
- Threat severity and behavior
- Risk of detection by RAT
- Effectiveness against this RAT type
- Whether it's a mutation (may have adapted)

Respond in JSON format:
{
    "primary_technique": "technique_name",
    "secondary_technique": "backup_technique",
    "reasoning": "why this strategy",
    "aggression_level": "low/medium/high",
    "expected_success_rate": 0.0-1.0,
    "special_instructions": "any specific actions"
}"""
            ).with_model("openai", "gpt-4o")
            
            # Include past tactics if available
            context = f"Threat Data: {threat_data}\n"
            if self.tactics_memory:
                context += f"Past successful tactics: {self.tactics_memory[-5:]}"
            
            response = await chat.send_message(UserMessage(text=context))
            
            # Parse JSON response
            import json
            try:
                # Extract JSON from response
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                if json_start != -1 and json_end > json_start:
                    strategy = json.loads(response[json_start:json_end])
                    return strategy
            except:
                pass
            
            return {
                "primary_technique": "network_isolation",
                "secondary_technique": "process_termination",
                "reasoning": response[:200],
                "aggression_level": "medium",
                "expected_success_rate": 0.75
            }
            
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return {
                "primary_technique": "network_isolation",
                "secondary_technique": "process_termination", 
                "reasoning": f"Fallback strategy due to error: {str(e)}",
                "aggression_level": "medium",
                "expected_success_rate": 0.7
            }
    
    async def detect_mutation(self, current_threat: dict, known_threats: List[dict]) -> dict:
        """Detect if threat is a mutation of known threat"""
        if not EMERGENT_LLM_KEY:
            return {"is_mutation": False, "parent": None}
        
        try:
            chat = LlmChat(
                api_key=EMERGENT_LLM_KEY,
                session_id=f"mutation-{self.session_id}",
                system_message="""You are a malware mutation detection AI. Analyze if the current threat is a mutation/variant of known threats.

Consider:
- Similar process names (with variations)
- Same port usage patterns
- Similar behavioral signatures
- Code evolution patterns

Respond JSON:
{
    "is_mutation": true/false,
    "confidence": 0.0-1.0,
    "parent_threat": "name or null",
    "mutation_type": "polymorphic/metamorphic/variant/new",
    "adaptation_detected": "what changed"
}"""
            ).with_model("openai", "gpt-4o")
            
            response = await chat.send_message(UserMessage(
                text=f"Current threat: {current_threat}\nKnown threats: {known_threats[:5]}"
            ))
            
            import json
            try:
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                if json_start != -1:
                    return json.loads(response[json_start:json_end])
            except:
                pass
                
            return {"is_mutation": False, "parent": None, "confidence": 0}
            
        except Exception as e:
            return {"is_mutation": False, "parent": None, "error": str(e)}
    
    async def learn_from_encounter(self, threat: dict, countermeasure: dict, success: bool) -> dict:
        """AI learns from encounter to improve future responses"""
        if not EMERGENT_LLM_KEY:
            return {"tactics_learned": [], "insight": "Learning unavailable"}
        
        try:
            chat = LlmChat(
                api_key=EMERGENT_LLM_KEY,
                session_id=f"learn-{self.session_id}",
                system_message="""You are a tactical learning AI for RAT countermeasures. Analyze the encounter and extract learnings.

Extract:
1. What worked/didn't work
2. Patterns to remember
3. Improved tactics for next time
4. Weakness discovered in threat

Respond JSON:
{
    "tactics_learned": ["tactic1", "tactic2"],
    "threat_weakness": "discovered weakness or null",
    "recommended_adjustment": "what to do differently",
    "confidence_boost": 0.0-0.2,
    "add_to_signatures": true/false
}"""
            ).with_model("openai", "gpt-4o")
            
            response = await chat.send_message(UserMessage(
                text=f"Threat: {threat}\nCountermeasure: {countermeasure}\nSuccess: {success}"
            ))
            
            import json
            try:
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                if json_start != -1:
                    learning = json.loads(response[json_start:json_end])
                    if success and learning.get("tactics_learned"):
                        self.tactics_memory.extend(learning["tactics_learned"])
                    return learning
            except:
                pass
            
            return {"tactics_learned": [], "insight": response[:200]}
            
        except Exception as e:
            return {"tactics_learned": [], "error": str(e)}

# Global agent instance
agent = RATCountermeasureAgent()

# ============== COUNTERMEASURE EXECUTION ==============
async def execute_countermeasure(technique: str, threat: dict) -> dict:
    """Execute a countermeasure technique (simulated)"""
    
    technique_info = COUNTERMEASURE_TECHNIQUES.get(technique, COUNTERMEASURE_TECHNIQUES["process_termination"])
    base_success = technique_info["effectiveness"]
    
    # Simulate execution with some randomness
    await asyncio.sleep(random.uniform(0.5, 2.0))  # Simulate execution time
    
    # Calculate success based on technique effectiveness and threat severity
    severity_modifier = {"critical": -0.2, "high": -0.1, "medium": 0, "low": 0.1}.get(threat.get("severity", "medium"), 0)
    success_chance = min(0.95, max(0.3, base_success + severity_modifier + random.uniform(-0.1, 0.1)))
    
    success = random.random() < success_chance
    
    result = {
        "technique": technique,
        "technique_name": technique_info["name"],
        "success": success,
        "execution_time": random.uniform(0.5, 2.0),
        "details": {}
    }
    
    if technique == "fault_injection":
        result["details"] = {
            "faults_injected": random.randint(3, 10),
            "target_functions": ["connect", "send", "recv", "CreateThread"],
            "crash_induced": success
        }
    elif technique == "resource_starvation":
        result["details"] = {
            "cpu_limited_to": f"{random.randint(1, 5)}%",
            "memory_capped": f"{random.randint(10, 50)}MB",
            "io_throttled": True,
            "process_slowed": success
        }
    elif technique == "network_isolation":
        result["details"] = {
            "connections_blocked": random.randint(1, 5),
            "ports_firewalled": random.sample(SUSPICIOUS_PORTS, min(3, len(SUSPICIOUS_PORTS))),
            "c2_communication_cut": success
        }
    elif technique == "process_termination":
        result["details"] = {
            "signal_sent": "SIGKILL",
            "child_processes_killed": random.randint(0, 3),
            "process_terminated": success
        }
    elif technique == "memory_corruption":
        result["details"] = {
            "memory_regions_corrupted": random.randint(2, 8),
            "heap_sprayed": True,
            "stack_smashed": success
        }
    elif technique == "decoy_deployment":
        result["details"] = {
            "decoys_deployed": random.randint(5, 15),
            "honeypot_files_created": random.randint(10, 30),
            "rat_confused": success
        }
    elif technique == "entropic_flood_poetic":
        # Use the Phi-Pi-Entropy engine for poetic mode disintegration
        disintegration = entropic_neutralizer.disintegrate(threat, mode="poetic")
        success = disintegration["success"]
        result["success"] = success
        result["details"] = {
            "mode": "poetic",
            "formula": "S(n) ≈ Φ·S(n-1) + (π/ln n)·e^(-n/ln(n+2))",
            "initial_entropy": disintegration["initial_entropy"],
            "flood_energy": disintegration["flood_energy"],
            "entropy_delta": disintegration["entropy_delta"],
            "net_zero_achieved": disintegration["net_zero_achieved"],
            "conjugate_inversion_applied": True,
            "chaos_seed": disintegration["signature"]
        }
    elif technique == "entropic_flood_brute":
        # Use the Phi-Pi-Entropy engine for brute mode disintegration
        disintegration = entropic_neutralizer.disintegrate(threat, mode="brute")
        success = disintegration["success"]
        result["success"] = success
        result["details"] = {
            "mode": "brute",
            "formula": "r=4.0 logistic chaos × 3 assaults",
            "initial_entropy": disintegration["initial_entropy"],
            "total_flood_energy": disintegration["total_flood_energy"],
            "overwhelming_ratio": disintegration["overwhelming_ratio"],
            "assault_count": disintegration["assault_count"],
            "entropy_overwhelmed": success
        }
    
    return result

# ============== AUTONOMOUS AGENT LOOP ==============
async def run_agent_cycle():
    """Run one cycle of the autonomous agent"""
    
    # Get active threats
    active_threats = await db.detections.find({"status": "active"}, {"_id": 0}).to_list(100)
    
    if not active_threats:
        return {"action": "patrol", "threats_processed": 0}
    
    results = []
    
    for threat in active_threats:
        # 1. Analyze threat with AI
        strategy = await agent.analyze_threat(threat)
        
        # Log war entry - detection analysis
        war_entry = WarLogEntry(
            event_type="analysis",
            threat_id=threat["id"],
            threat_name=threat["threat_name"],
            description=f"AI analyzed threat: {threat['threat_name']}",
            ai_decision=f"Strategy: {strategy.get('primary_technique')} | Reasoning: {strategy.get('reasoning', '')[:100]}"
        )
        await db.war_log.insert_one({**war_entry.model_dump(), "timestamp": war_entry.timestamp.isoformat()})
        
        # 2. Check for mutation
        known_threats = await db.threat_intelligence.find({}, {"_id": 0}).to_list(50)
        mutation_check = await agent.detect_mutation(threat, known_threats)
        
        if mutation_check.get("is_mutation"):
            # Log mutation detection
            mut_entry = WarLogEntry(
                event_type="mutation",
                threat_id=threat["id"],
                threat_name=threat["threat_name"],
                description=f"MUTATION DETECTED: {threat['threat_name']} is variant of {mutation_check.get('parent_threat')}",
                ai_decision=f"Confidence: {mutation_check.get('confidence', 0):.0%} | Type: {mutation_check.get('mutation_type')}"
            )
            await db.war_log.insert_one({**mut_entry.model_dump(), "timestamp": mut_entry.timestamp.isoformat()})
            
            # Update threat record
            await db.detections.update_one(
                {"id": threat["id"]},
                {"$set": {"mutation_detected": True, "parent_threat_id": mutation_check.get("parent_threat")}}
            )
        
        # 3. Execute primary countermeasure
        primary_result = await execute_countermeasure(strategy.get("primary_technique", "network_isolation"), threat)
        
        # Log countermeasure
        cm_entry = WarLogEntry(
            event_type="countermeasure",
            threat_id=threat["id"],
            threat_name=threat["threat_name"],
            description=f"Deployed {primary_result['technique_name']}",
            ai_decision=strategy.get("reasoning", "")[:150],
            outcome="SUCCESS" if primary_result["success"] else "FAILED"
        )
        await db.war_log.insert_one({**cm_entry.model_dump(), "timestamp": cm_entry.timestamp.isoformat()})
        
        # Store countermeasure record
        countermeasure = Countermeasure(
            detection_id=threat["id"],
            technique=primary_result["technique"],
            action_taken=str(primary_result["details"]),
            success=primary_result["success"],
            ai_reasoning=strategy.get("reasoning", "")
        )
        await db.countermeasures.insert_one({**countermeasure.model_dump(), "timestamp": countermeasure.timestamp.isoformat()})
        
        # 4. If primary failed, try secondary
        if not primary_result["success"] and strategy.get("secondary_technique"):
            secondary_result = await execute_countermeasure(strategy["secondary_technique"], threat)
            
            sec_entry = WarLogEntry(
                event_type="escalation",
                threat_id=threat["id"],
                threat_name=threat["threat_name"],
                description=f"Primary failed, escalating to {secondary_result['technique_name']}",
                outcome="SUCCESS" if secondary_result["success"] else "FAILED"
            )
            await db.war_log.insert_one({**sec_entry.model_dump(), "timestamp": sec_entry.timestamp.isoformat()})
            
            if secondary_result["success"]:
                primary_result = secondary_result
        
        # 5. Update threat status if evicted
        if primary_result["success"]:
            await db.detections.update_one({"id": threat["id"]}, {"$set": {"status": "evicted"}})
            
            evict_entry = WarLogEntry(
                event_type="eviction",
                threat_id=threat["id"],
                threat_name=threat["threat_name"],
                description=f"THREAT EVICTED: {threat['threat_name']} successfully removed",
                outcome="EVICTED"
            )
            await db.war_log.insert_one({**evict_entry.model_dump(), "timestamp": evict_entry.timestamp.isoformat()})
        
        # 6. Learn from encounter
        learning = await agent.learn_from_encounter(threat, primary_result, primary_result["success"])
        
        if learning.get("tactics_learned"):
            learn_entry = WarLogEntry(
                event_type="learning",
                threat_id=threat["id"],
                threat_name=threat["threat_name"],
                description=f"Agent learned from encounter",
                tactics_learned=learning.get("tactics_learned", []),
                ai_decision=learning.get("recommended_adjustment", "")
            )
            await db.war_log.insert_one({**learn_entry.model_dump(), "timestamp": learn_entry.timestamp.isoformat()})
            
            # Store in threat intelligence
            if learning.get("add_to_signatures"):
                intel = {
                    "id": str(uuid.uuid4()),
                    "threat_name": threat["threat_name"],
                    "known_behaviors": threat.get("behavioral_profile", []),
                    "effective_countermeasures": [primary_result["technique"]] if primary_result["success"] else [],
                    "weakness_discovered": learning.get("threat_weakness"),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                await db.threat_intelligence.update_one(
                    {"threat_name": threat["threat_name"]},
                    {"$set": intel},
                    upsert=True
                )
        
        results.append({
            "threat_id": threat["id"],
            "threat_name": threat["threat_name"],
            "strategy": strategy,
            "result": primary_result,
            "mutation": mutation_check,
            "learning": learning
        })
    
    # Update agent state
    evicted = sum(1 for r in results if r["result"]["success"])
    await db.agent_state.update_one(
        {"id": "agent_state_singleton"},
        {
            "$inc": {
                "threats_evicted": evicted,
                "countermeasures_deployed": len(results),
                "learning_iterations": 1
            },
            "$set": {
                "threats_active": len(active_threats) - evicted,
                "last_action": f"Processed {len(results)} threats, evicted {evicted}",
                "last_action_time": datetime.now(timezone.utc).isoformat()
            }
        },
        upsert=True
    )
    
    return {"action": "countermeasure_cycle", "threats_processed": len(results), "evicted": evicted, "details": results}

# ============== API ROUTES ==============
@api_router.get("/")
async def root():
    return {"message": "RAT Detection & Countermeasure API v2.0", "agent": "autonomous"}

@api_router.get("/status")
async def get_system_status():
    """Get current system and agent status"""
    active_threats = await db.detections.count_documents({"status": "active"})
    evicted_threats = await db.detections.count_documents({"status": "evicted"})
    total_detections = await db.detections.count_documents({})
    mutations = await db.detections.count_documents({"mutation_detected": True})
    countermeasures = await db.countermeasures.count_documents({})
    
    agent_state = await db.agent_state.find_one({"id": "agent_state_singleton"}, {"_id": 0})
    
    threat_level = "safe"
    if active_threats > 5:
        threat_level = "critical"
    elif active_threats > 2:
        threat_level = "danger"
    elif active_threats > 0:
        threat_level = "warning"
    
    return {
        "cpu_usage": round(random.uniform(15, 45), 1),
        "memory_usage": round(random.uniform(40, 70), 1),
        "active_connections": random.randint(20, 80),
        "active_threats": active_threats,
        "evicted_threats": evicted_threats,
        "total_detections": total_detections,
        "mutations_detected": mutations,
        "countermeasures_deployed": countermeasures,
        "threat_level": threat_level,
        "agent_state": agent_state,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@api_router.post("/scan")
async def start_scan(background_tasks: BackgroundTasks):
    """Start a system scan and trigger agent response"""
    
    detections = []
    items_scanned = random.randint(2000, 8000)
    
    # Simulate finding multiple threats (RATs trying to replicate)
    num_threats = random.randint(1, 4)
    for _ in range(num_threats):
        rat = random.choice(RAT_SIGNATURES)
        
        # Generate signature hash for mutation detection
        sig_data = f"{rat['name']}{random.randint(1,1000)}"
        sig_hash = hashlib.md5(sig_data.encode()).hexdigest()
        
        detection = Detection(
            detection_type=random.choice(["rat_signature", "suspicious_connection", "behavioral_anomaly"]),
            threat_name=rat["name"],
            severity=random.choice(["critical", "high", "medium"]),
            signature_hash=sig_hash,
            behavioral_profile=random.sample(rat["behaviors"], min(2, len(rat["behaviors"]))),
            details={
                "matched_process": random.choice(rat["processes"]),
                "matched_port": random.choice(rat["ports"]),
                "location": f"C:\\Users\\User\\AppData\\Local\\Temp\\{random.choice(rat['processes'])}",
                "md5_hash": uuid.uuid4().hex[:32],
                "behaviors_detected": random.sample(rat["behaviors"], min(2, len(rat["behaviors"])))
            }
        )
        
        doc = detection.model_dump()
        doc['timestamp'] = doc['timestamp'].isoformat()
        await db.detections.insert_one(doc)
        # Create a clean copy without MongoDB _id
        clean_doc = {k: v for k, v in doc.items() if k != '_id'}
        detections.append(clean_doc)
        
        # Log to war log
        war_entry = WarLogEntry(
            event_type="detection",
            threat_id=detection.id,
            threat_name=detection.threat_name,
            description=f"NEW THREAT DETECTED: {detection.threat_name} ({detection.severity})",
            ai_decision="Queued for autonomous countermeasure"
        )
        await db.war_log.insert_one({**war_entry.model_dump(), "timestamp": war_entry.timestamp.isoformat()})
    
    # Trigger autonomous agent in background
    background_tasks.add_task(run_agent_cycle)
    
    return {
        "scan_id": str(uuid.uuid4()),
        "items_scanned": items_scanned,
        "threats_found": len(detections),
        "detections": detections,
        "agent_triggered": True
    }

@api_router.post("/agent/run")
async def trigger_agent_cycle():
    """Manually trigger an agent cycle"""
    result = await run_agent_cycle()
    return result

@api_router.get("/agent/state")
async def get_agent_state():
    """Get current agent state"""
    state = await db.agent_state.find_one({"id": "agent_state_singleton"}, {"_id": 0})
    if not state:
        state = AgentState().model_dump()
    else:
        # Ensure default values for missing fields
        default_state = AgentState().model_dump()
        for key, value in default_state.items():
            if key not in state:
                state[key] = value
    return state

@api_router.post("/agent/mode")
async def set_agent_mode(mode: str):
    """Set agent operating mode"""
    if mode not in ["autonomous", "defensive", "aggressive"]:
        raise HTTPException(status_code=400, detail="Invalid mode")
    
    await db.agent_state.update_one(
        {"id": "agent_state_singleton"},
        {"$set": {"mode": mode}},
        upsert=True
    )
    return {"message": f"Agent mode set to {mode}"}

@api_router.get("/detections")
async def get_detections(status: Optional[str] = None, limit: int = 50):
    """Get all detections"""
    query = {}
    if status:
        query["status"] = status
    
    detections = await db.detections.find(query, {"_id": 0}).sort("timestamp", -1).to_list(limit)
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
    
    strategy = await agent.analyze_threat(detection)
    
    await db.detections.update_one(
        {"id": detection_id},
        {"$set": {"ai_analysis": str(strategy)}}
    )
    
    return {"detection_id": detection_id, "strategy": strategy}

@api_router.get("/war-log")
async def get_war_log(limit: int = 100, event_type: Optional[str] = None):
    """Get the war log"""
    query = {}
    if event_type:
        query["event_type"] = event_type
    
    entries = await db.war_log.find(query, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    return entries

@api_router.get("/countermeasures")
async def get_countermeasures(limit: int = 50):
    """Get countermeasure history"""
    cms = await db.countermeasures.find({}, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    return cms

@api_router.get("/countermeasures/techniques")
async def get_techniques():
    """Get available countermeasure techniques"""
    return COUNTERMEASURE_TECHNIQUES

@api_router.get("/network/connections")
async def get_network_connections():
    """Get simulated network connections"""
    connections = []
    for _ in range(random.randint(15, 35)):
        is_suspicious = random.random() < 0.2
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
            "blocked": is_suspicious and random.random() < 0.5,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        connections.append(conn)
    
    return connections

@api_router.get("/threat-intelligence")
async def get_threat_intelligence():
    """Get learned threat intelligence"""
    intel = await db.threat_intelligence.find({}, {"_id": 0}).to_list(100)
    return intel

@api_router.get("/stats")
async def get_statistics():
    """Get comprehensive statistics"""
    total_scans = await db.scans.count_documents({}) if "scans" in await db.list_collection_names() else 0
    total_detections = await db.detections.count_documents({})
    active_threats = await db.detections.count_documents({"status": "active"})
    evicted_threats = await db.detections.count_documents({"status": "evicted"})
    mutations = await db.detections.count_documents({"mutation_detected": True})
    total_countermeasures = await db.countermeasures.count_documents({})
    successful_countermeasures = await db.countermeasures.count_documents({"success": True})
    
    # Countermeasures by technique
    cm_pipeline = [{"$group": {"_id": "$technique", "count": {"$sum": 1}, "success": {"$sum": {"$cond": ["$success", 1, 0]}}}}]
    by_technique = await db.countermeasures.aggregate(cm_pipeline).to_list(100)
    
    # War log stats
    war_events = await db.war_log.count_documents({})
    
    return {
        "total_detections": total_detections,
        "active_threats": active_threats,
        "evicted_threats": evicted_threats,
        "mutations_detected": mutations,
        "total_countermeasures": total_countermeasures,
        "successful_countermeasures": successful_countermeasures,
        "success_rate": (successful_countermeasures / total_countermeasures * 100) if total_countermeasures > 0 else 0,
        "by_technique": {item["_id"]: {"total": item["count"], "success": item["success"]} for item in by_technique if item["_id"]},
        "war_log_entries": war_events,
        "agent_tactics_learned": len(agent.tactics_memory)
    }

@api_router.get("/signatures")
async def get_rat_signatures():
    """Get known RAT signatures"""
    return RAT_SIGNATURES

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
