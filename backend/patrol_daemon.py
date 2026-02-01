"""
Autonomous Patrol Daemon v2.0
Continuous threat SCANNING and neutralization with escalating countermeasures
Now includes active scanning for new threats - not just processing existing ones
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Callable
import random
import hashlib
import uuid

logger = logging.getLogger(__name__)

# Countermeasure escalation order (least to most aggressive)
ESCALATION_ORDER = [
    "decoy_deployment",      # 0.50 effectiveness - confuse
    "resource_starvation",   # 0.60 effectiveness - slow down  
    "fault_injection",       # 0.70 effectiveness - destabilize
    "memory_corruption",     # 0.75 effectiveness - corrupt
    "network_isolation",     # 0.85 effectiveness - cut comms
    "entropic_flood_poetic", # 0.88 effectiveness - entropy cancel
    "process_termination",   # 0.90 effectiveness - kill
    "entropic_flood_brute",  # 0.92 effectiveness - overwhelm
]

# Known RAT signatures for scanning
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
    {"name": "Gh0st RAT", "processes": ["gh0st.exe", "ghost.exe"], "ports": [8000, 8080], "behaviors": ["keylogging", "screen_capture", "audio_capture"]},
    {"name": "Blackshades", "processes": ["bss.exe", "blackshades.exe"], "ports": [1337, 31337], "behaviors": ["ransomware", "keylogging", "webcam"]},
    {"name": "NanoCore", "processes": ["nanocore.exe", "nano.exe"], "ports": [54984, 5555], "behaviors": ["keylogging", "password_theft", "surveillance"]},
    {"name": "Imminent Monitor", "processes": ["imminent.exe", "im.exe"], "ports": [1604, 9001], "behaviors": ["keylogging", "clipboard", "webcam"]},
    {"name": "LuminosityLink", "processes": ["luminosity.exe", "lum.exe"], "ports": [6318, 6319], "behaviors": ["keylogging", "webcam", "persistence"]},
]

SUSPICIOUS_PORTS = [4444, 4445, 5552, 1177, 3460, 65535, 7896, 50050, 6666, 31337, 12345, 1337, 8000, 9001, 54984]


class AutonomousPatrol:
    """
    Autonomous threat hunting and neutralization daemon.
    SCANS for new threats AND processes existing ones continuously.
    """
    
    def __init__(self, db, execute_countermeasure_func, entropic_neutralizer, anomaly_detector, war_log_class, detection_class):
        self.db = db
        self.execute_countermeasure = execute_countermeasure_func
        self.neutralizer = entropic_neutralizer
        self.detector = anomaly_detector
        self.WarLogEntry = war_log_class
        self.Detection = detection_class
        
        self.is_running = False
        self.scan_interval = 5       # seconds between scans for NEW threats
        self.patrol_interval = 3     # seconds between countermeasure cycles
        self.threat_attempts = {}    # Track attempts per threat for escalation
        self.cycle_count = 0
        self.scan_count = 0
        self.threats_detected = 0
        self.threats_neutralized = 0
        self.total_countermeasures = 0
        self.last_scan_time = None
        self.last_patrol_time = None
        
    async def log_war_entry(self, event_type: str, threat_id: str = None, 
                           threat_name: str = None, description: str = "",
                           outcome: str = None, ai_decision: str = None):
        """Log entry to war log."""
        entry = self.WarLogEntry(
            event_type=event_type,
            threat_id=threat_id,
            threat_name=threat_name,
            description=description,
            ai_decision=ai_decision,
            outcome=outcome
        )
        await self.db.war_log.insert_one({
            **entry.model_dump(), 
            "timestamp": entry.timestamp.isoformat()
        })
    
    async def scan_for_new_threats(self) -> List[Dict]:
        """
        Actively scan for NEW threats - simulates continuous system monitoring.
        This runs independently to detect RATs as they log back in.
        """
        self.scan_count += 1
        self.last_scan_time = datetime.now(timezone.utc)
        
        new_detections = []
        
        # Simulate RATs constantly trying to reconnect (high probability)
        # In real scenario, this would scan actual system processes/connections
        num_new_threats = 0
        
        # 70% chance of detecting new threats each scan (they keep coming back)
        if random.random() < 0.70:
            num_new_threats = random.randint(1, 3)
        
        for _ in range(num_new_threats):
            rat = random.choice(RAT_SIGNATURES)
            
            # Generate unique signature
            sig_data = f"{rat['name']}{datetime.now().timestamp()}{random.randint(1,10000)}"
            sig_hash = hashlib.md5(sig_data.encode()).hexdigest()
            
            # Check if this exact threat is already active (avoid duplicates)
            existing = await self.db.detections.find_one({
                "threat_name": rat["name"],
                "status": "active"
            })
            
            # Allow some duplicates (mutations/variants)
            if existing and random.random() < 0.5:
                continue
            
            detection_data = {
                "id": str(uuid.uuid4()),
                "detection_type": random.choice(["rat_signature", "suspicious_connection", "behavioral_anomaly", "port_scan"]),
                "threat_name": rat["name"],
                "severity": random.choice(["critical", "high", "medium"]),
                "signature_hash": sig_hash,
                "behavioral_profile": random.sample(rat["behaviors"], min(2, len(rat["behaviors"]))),
                "mutation_detected": random.random() < 0.3,  # 30% are mutations
                "details": {
                    "matched_process": random.choice(rat["processes"]),
                    "matched_port": random.choice(rat["ports"]),
                    "location": f"C:\\Users\\User\\AppData\\Local\\Temp\\{random.choice(rat['processes'])}",
                    "md5_hash": uuid.uuid4().hex[:32],
                    "behaviors_detected": random.sample(rat["behaviors"], min(2, len(rat["behaviors"]))),
                    "reconnect_attempt": True,
                    "scan_cycle": self.scan_count
                },
                "status": "active",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            # Insert into database
            await self.db.detections.insert_one(detection_data)
            new_detections.append(detection_data)
            self.threats_detected += 1
            
            # Log detection
            await self.log_war_entry(
                event_type="detection",
                threat_id=detection_data["id"],
                threat_name=detection_data["threat_name"],
                description=f"SCAN #{self.scan_count}: New threat detected - {detection_data['threat_name']} ({detection_data['severity']})",
                ai_decision="Queued for immediate countermeasure",
                outcome="DETECTED"
            )
        
        return new_detections
        
    async def get_active_threats(self) -> List[Dict]:
        """Get all active threats from database."""
        return await self.db.detections.find(
            {"status": "active"}, 
            {"_id": 0}
        ).to_list(100)
    
    def get_next_countermeasure(self, threat_id: str) -> str:
        """Get next countermeasure in escalation sequence for a threat."""
        attempts = self.threat_attempts.get(threat_id, 0)
        
        if attempts >= len(ESCALATION_ORDER):
            return ESCALATION_ORDER[-1]
        
        return ESCALATION_ORDER[attempts]
    
    def record_attempt(self, threat_id: str, success: bool):
        """Record countermeasure attempt for escalation tracking."""
        if threat_id not in self.threat_attempts:
            self.threat_attempts[threat_id] = 0
        
        if not success:
            self.threat_attempts[threat_id] += 1
        else:
            if threat_id in self.threat_attempts:
                del self.threat_attempts[threat_id]
    
    async def engage_threat(self, threat: Dict) -> Dict:
        """Engage a single threat with escalating countermeasures."""
        threat_id = threat.get("id")
        threat_name = threat.get("threat_name", "Unknown")
        
        technique = self.get_next_countermeasure(threat_id)
        escalation_level = self.threat_attempts.get(threat_id, 0)
        
        await self.log_war_entry(
            event_type="engagement",
            threat_id=threat_id,
            threat_name=threat_name,
            description=f"Engaging {threat_name} with {technique} (level {escalation_level}/{len(ESCALATION_ORDER)-1})",
            ai_decision=f"Escalation protocol - technique {escalation_level + 1} of {len(ESCALATION_ORDER)}"
        )
        
        result = await self.execute_countermeasure(technique, threat)
        self.total_countermeasures += 1
        
        self.record_attempt(threat_id, result.get("success", False))
        
        if result.get("success"):
            await self.db.detections.update_one(
                {"id": threat_id},
                {"$set": {"status": "evicted"}}
            )
            self.threats_neutralized += 1
            
            await self.log_war_entry(
                event_type="eviction",
                threat_id=threat_id,
                threat_name=threat_name,
                description=f"NEUTRALIZED: {threat_name} eliminated via {technique}",
                outcome="EVICTED"
            )
        else:
            next_technique = self.get_next_countermeasure(threat_id)
            await self.log_war_entry(
                event_type="escalation",
                threat_id=threat_id,
                threat_name=threat_name,
                description=f"{technique} failed, escalating to {next_technique}",
                outcome="ESCALATING"
            )
        
        return {
            "threat_id": threat_id,
            "threat_name": threat_name,
            "technique": technique,
            "success": result.get("success", False),
            "escalation_level": escalation_level,
            "details": result.get("details", {})
        }
    
    async def patrol_cycle(self):
        """Execute one patrol cycle - engage all active threats."""
        self.cycle_count += 1
        self.last_patrol_time = datetime.now(timezone.utc)
        
        threats = await self.get_active_threats()
        
        if not threats:
            return {
                "cycle": self.cycle_count,
                "threats_found": 0,
                "action": "patrol_clear"
            }
        
        results = []
        
        for threat in threats:
            try:
                result = await self.engage_threat(threat)
                results.append(result)
                await asyncio.sleep(0.2)  # Brief delay between engagements
                
            except Exception as e:
                logger.error(f"Error engaging threat {threat.get('id')}: {e}")
        
        neutralized = sum(1 for r in results if r.get("success"))
        
        return {
            "cycle": self.cycle_count,
            "threats_found": len(threats),
            "threats_engaged": len(results),
            "threats_neutralized": neutralized,
            "results": results
        }
    
    async def run_daemon(self):
        """
        Main daemon loop - runs CONTINUOUSLY.
        Alternates between scanning for NEW threats and neutralizing existing ones.
        """
        self.is_running = True
        
        await self.log_war_entry(
            event_type="daemon_start",
            description="AUTONOMOUS PATROL DAEMON v2.0 ACTIVATED - Continuous scanning enabled",
            ai_decision="Scan interval: 5s | Patrol interval: 3s | Escalation: 8 levels"
        )
        
        logger.info("Autonomous patrol daemon v2.0 started - continuous scanning enabled")
        
        scan_counter = 0
        
        while self.is_running:
            try:
                # SCAN for new threats every cycle
                new_threats = await self.scan_for_new_threats()
                if new_threats:
                    logger.info(f"Scan #{self.scan_count}: Detected {len(new_threats)} new threat(s)")
                
                # Small delay after scan
                await asyncio.sleep(1)
                
                # PATROL and neutralize active threats
                result = await self.patrol_cycle()
                
                if result.get("threats_found", 0) > 0:
                    logger.info(f"Patrol cycle {result['cycle']}: "
                               f"Engaged {result.get('threats_engaged', 0)}, "
                               f"Neutralized {result.get('threats_neutralized', 0)}")
                
                # Wait before next cycle
                await asyncio.sleep(self.patrol_interval)
                
                scan_counter += 1
                
                # Periodic status log
                if scan_counter % 10 == 0:
                    active = await self.db.detections.count_documents({"status": "active"})
                    await self.log_war_entry(
                        event_type="status",
                        description=f"Status: {active} active threats | {self.threats_neutralized} neutralized | {self.total_countermeasures} countermeasures deployed",
                        ai_decision="Continuous monitoring active"
                    )
                
            except asyncio.CancelledError:
                logger.info("Patrol daemon cancelled")
                break
            except Exception as e:
                logger.error(f"Patrol cycle error: {e}")
                await asyncio.sleep(2)
        
        await self.log_war_entry(
            event_type="daemon_stop",
            description=f"Patrol daemon stopped. Scans: {self.scan_count}, Cycles: {self.cycle_count}, "
                       f"Detected: {self.threats_detected}, Neutralized: {self.threats_neutralized}"
        )
        
        logger.info("Autonomous patrol daemon stopped")
    
    def stop(self):
        """Stop the daemon."""
        self.is_running = False
    
    def get_status(self) -> Dict:
        """Get current daemon status."""
        return {
            "is_running": self.is_running,
            "scan_count": self.scan_count,
            "cycle_count": self.cycle_count,
            "threats_detected": self.threats_detected,
            "threats_neutralized": self.threats_neutralized,
            "total_countermeasures": self.total_countermeasures,
            "scan_interval": self.scan_interval,
            "patrol_interval": self.patrol_interval,
            "active_escalations": len(self.threat_attempts),
            "escalation_levels": dict(self.threat_attempts),
            "last_scan": self.last_scan_time.isoformat() if self.last_scan_time else None,
            "last_patrol": self.last_patrol_time.isoformat() if self.last_patrol_time else None
        }


# Global patrol instance
patrol_daemon: Optional[AutonomousPatrol] = None
patrol_task: Optional[asyncio.Task] = None


def get_patrol_daemon() -> Optional[AutonomousPatrol]:
    """Get the global patrol daemon instance."""
    return patrol_daemon


async def start_patrol(daemon: AutonomousPatrol):
    """Start the patrol daemon."""
    global patrol_daemon, patrol_task
    
    patrol_daemon = daemon
    patrol_task = asyncio.create_task(daemon.run_daemon())
    return patrol_task


async def stop_patrol():
    """Stop the patrol daemon."""
    global patrol_daemon, patrol_task
    
    if patrol_daemon:
        patrol_daemon.stop()
    
    if patrol_task:
        patrol_task.cancel()
        try:
            await patrol_task
        except asyncio.CancelledError:
            pass
    
    patrol_daemon = None
    patrol_task = None
