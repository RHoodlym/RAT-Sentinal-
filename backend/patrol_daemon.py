"""
Autonomous Patrol Daemon
Continuous threat monitoring and escalating countermeasure deployment
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
import random

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

class AutonomousPatrol:
    """
    Autonomous threat hunting and neutralization daemon.
    Runs continuously, escalating countermeasures from gentle to aggressive.
    """
    
    def __init__(self, db, execute_countermeasure_func, entropic_neutralizer, anomaly_detector, war_log_class):
        self.db = db
        self.execute_countermeasure = execute_countermeasure_func
        self.neutralizer = entropic_neutralizer
        self.detector = anomaly_detector
        self.WarLogEntry = war_log_class
        
        self.is_running = False
        self.patrol_interval = 10  # seconds between patrol cycles
        self.scan_interval = 30    # seconds between full scans
        self.threat_attempts = {}  # Track attempts per threat for escalation
        self.cycle_count = 0
        self.threats_neutralized = 0
        self.total_countermeasures = 0
        
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
            # Cycle back to most aggressive
            return ESCALATION_ORDER[-1]
        
        return ESCALATION_ORDER[attempts]
    
    def record_attempt(self, threat_id: str, success: bool):
        """Record countermeasure attempt for escalation tracking."""
        if threat_id not in self.threat_attempts:
            self.threat_attempts[threat_id] = 0
        
        if not success:
            # Escalate to next level
            self.threat_attempts[threat_id] += 1
        else:
            # Reset on success
            del self.threat_attempts[threat_id]
    
    async def engage_threat(self, threat: Dict) -> Dict:
        """Engage a single threat with escalating countermeasures."""
        threat_id = threat.get("id")
        threat_name = threat.get("threat_name", "Unknown")
        
        # Get next countermeasure in escalation
        technique = self.get_next_countermeasure(threat_id)
        escalation_level = self.threat_attempts.get(threat_id, 0)
        
        await self.log_war_entry(
            event_type="engagement",
            threat_id=threat_id,
            threat_name=threat_name,
            description=f"Engaging {threat_name} with {technique} (escalation level {escalation_level})",
            ai_decision=f"Auto-selected from escalation protocol"
        )
        
        # Execute countermeasure
        result = await self.execute_countermeasure(technique, threat)
        self.total_countermeasures += 1
        
        # Record attempt for escalation tracking
        self.record_attempt(threat_id, result.get("success", False))
        
        if result.get("success"):
            # Mark threat as evicted
            await self.db.detections.update_one(
                {"id": threat_id},
                {"$set": {"status": "evicted"}}
            )
            self.threats_neutralized += 1
            
            await self.log_war_entry(
                event_type="eviction",
                threat_id=threat_id,
                threat_name=threat_name,
                description=f"NEUTRALIZED via {technique}",
                outcome="EVICTED"
            )
        else:
            next_technique = self.get_next_countermeasure(threat_id)
            await self.log_war_entry(
                event_type="escalation",
                threat_id=threat_id,
                threat_name=threat_name,
                description=f"{technique} insufficient, escalating to {next_technique}",
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
        """Execute one patrol cycle - scan and engage all active threats."""
        self.cycle_count += 1
        
        # Get active threats
        threats = await self.get_active_threats()
        
        if not threats:
            return {
                "cycle": self.cycle_count,
                "threats_found": 0,
                "action": "patrol_clear"
            }
        
        await self.log_war_entry(
            event_type="patrol",
            description=f"Patrol cycle {self.cycle_count}: {len(threats)} active threat(s) detected",
            ai_decision="Initiating autonomous engagement sequence"
        )
        
        results = []
        
        # Engage each threat
        for threat in threats:
            try:
                result = await self.engage_threat(threat)
                results.append(result)
                
                # Small delay between engagements
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Error engaging threat {threat.get('id')}: {e}")
                await self.log_war_entry(
                    event_type="error",
                    threat_id=threat.get("id"),
                    threat_name=threat.get("threat_name"),
                    description=f"Engagement error: {str(e)}",
                    outcome="ERROR"
                )
        
        neutralized = sum(1 for r in results if r.get("success"))
        
        return {
            "cycle": self.cycle_count,
            "threats_found": len(threats),
            "threats_engaged": len(results),
            "threats_neutralized": neutralized,
            "results": results
        }
    
    async def run_daemon(self):
        """Main daemon loop - runs continuously."""
        self.is_running = True
        
        await self.log_war_entry(
            event_type="daemon_start",
            description="Autonomous patrol daemon activated",
            ai_decision="Continuous monitoring initiated"
        )
        
        logger.info("Autonomous patrol daemon started")
        
        while self.is_running:
            try:
                # Run patrol cycle
                result = await self.patrol_cycle()
                
                if result.get("threats_found", 0) > 0:
                    logger.info(f"Patrol cycle {result['cycle']}: "
                               f"Engaged {result.get('threats_engaged', 0)}, "
                               f"Neutralized {result.get('threats_neutralized', 0)}")
                
                # Wait before next cycle
                await asyncio.sleep(self.patrol_interval)
                
            except asyncio.CancelledError:
                logger.info("Patrol daemon cancelled")
                break
            except Exception as e:
                logger.error(f"Patrol cycle error: {e}")
                await asyncio.sleep(5)  # Brief pause on error
        
        await self.log_war_entry(
            event_type="daemon_stop",
            description=f"Patrol daemon stopped. Cycles: {self.cycle_count}, "
                       f"Neutralized: {self.threats_neutralized}, "
                       f"Total countermeasures: {self.total_countermeasures}"
        )
        
        logger.info("Autonomous patrol daemon stopped")
    
    def stop(self):
        """Stop the daemon."""
        self.is_running = False
    
    def get_status(self) -> Dict:
        """Get current daemon status."""
        return {
            "is_running": self.is_running,
            "cycle_count": self.cycle_count,
            "threats_neutralized": self.threats_neutralized,
            "total_countermeasures": self.total_countermeasures,
            "patrol_interval": self.patrol_interval,
            "active_escalations": len(self.threat_attempts),
            "escalation_levels": dict(self.threat_attempts)
        }


# Global patrol instance (initialized in server.py)
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
