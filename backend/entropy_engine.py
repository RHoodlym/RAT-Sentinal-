"""
Entropy-Based Threat Detection & Neutralization Module
Autonomous countermeasure system with escalating response protocol
"""

import math
import hashlib
from typing import Dict, List, Optional
from datetime import datetime, timezone
import random

# Core constants (internal use only)
_PHI = (1 + math.sqrt(5)) / 2
_PI = math.pi
_R = 4.0

class EntropyEngine:
    """
    Entropy-based threat analysis and neutralization engine.
    Uses chaos theory and entropy scoring for advanced threat detection.
    """
    
    def __init__(self):
        self.entropy_cache = {}
        self.flood_history = []
        self.neutralization_count = 0
        
    def compute_entropy_score(self, n: int, s_prev: float = 1.0) -> float:
        """Compute entropy score using recursive dampening."""
        if n == 0:
            return s_prev
        
        n_safe = max(n, 2)
        ln_n = math.log(n_safe)
        ln_n_plus_2 = math.log(n_safe + 2)
        
        decay = math.exp(-n_safe / ln_n_plus_2)
        pi_term = (_PI / ln_n) * decay
        entropy = _PHI * s_prev + pi_term
        
        normalized = 1 / (1 + math.exp(-entropy + 2))
        return normalized
    
    def compute_sequence_entropy(self, data: str, window_size: int = 10) -> List[float]:
        """Compute rolling entropy scores for a data sequence."""
        tokens = data.split() if isinstance(data, str) else data
        scores = []
        s_prev = 1.0
        
        for i, token in enumerate(tokens):
            token_hash = hash(token) % 1000 / 1000.0
            s_n = self.compute_entropy_score(i + 1, s_prev)
            blended = (s_n * 0.7) + (token_hash * 0.3)
            scores.append(blended)
            s_prev = s_n
            
        return scores
    
    def logistic_map(self, x: float, r: float = _R) -> float:
        """Logistic map for chaotic sequence generation."""
        return r * x * (1 - x)
    
    def generate_chaos_sequence(self, seed: float, steps: int = 100) -> List[float]:
        """Generate chaotic sequence for neutralization."""
        x = max(0.001, min(0.999, seed))
        sequence = []
        
        for _ in range(steps):
            x = self.logistic_map(x)
            sequence.append(x)
            
        return sequence
    
    def conjugate_inversion(self, sequence: List[float]) -> List[float]:
        """Apply conjugate inversion for entropy cancellation."""
        return [1 - x for x in reversed(sequence)]
    
    def generate_entropic_flood(self, signature: str, intensity: int = 100) -> Dict:
        """Generate entropic flood for threat neutralization."""
        sig_hash = hashlib.sha256(signature.encode()).hexdigest()
        seed = int(sig_hash[:8], 16) / (16**8)
        
        forward_chaos = self.generate_chaos_sequence(seed, intensity)
        inverted_flood = self.conjugate_inversion(forward_chaos)
        
        flood_energy = sum(inverted_flood)
        flood_variance = sum((x - 0.5)**2 for x in inverted_flood) / len(inverted_flood)
        
        flood_data = {
            "signature": signature,
            "seed": seed,
            "intensity": intensity,
            "flood_energy": flood_energy,
            "flood_variance": flood_variance,
            "peak_amplitude": max(inverted_flood),
            "sequence_sample": inverted_flood[:10],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        self.flood_history.append(flood_data)
        return flood_data


class GraphAnomalyDetector:
    """Graph-based anomaly detection using entropy scoring."""
    
    def __init__(self, entropy_engine: EntropyEngine):
        self.engine = entropy_engine
        self.anomaly_threshold = 0.75
        
    def build_threat_graph(self, data: Dict) -> Dict:
        """Build a graph representation of threat data."""
        threat_name = data.get("threat_name", "unknown")
        details = data.get("details", {})
        behaviors = data.get("behavioral_profile", [])
        
        nodes = {}
        edges = []
        
        main_entropy = self.engine.compute_entropy_score(hash(threat_name) % 100, s_prev=0.5)
        nodes[threat_name] = {
            "entropy": main_entropy,
            "node_type": "threat",
            "risk_level": "high" if main_entropy > 0.7 else "medium"
        }
        
        for i, behavior in enumerate(behaviors):
            behavior_entropy = self.engine.compute_entropy_score(i + 1)
            node_key = f"behavior_{behavior}"
            nodes[node_key] = {
                "entropy": behavior_entropy,
                "node_type": "behavior",
                "name": behavior
            }
            edges.append((threat_name, node_key, abs(main_entropy - behavior_entropy)))
        
        if "matched_process" in details:
            proc = details["matched_process"]
            proc_entropy = self.engine.compute_entropy_score(hash(proc) % 50)
            nodes[f"process_{proc}"] = {
                "entropy": proc_entropy,
                "node_type": "process",
                "name": proc
            }
            edges.append((threat_name, f"process_{proc}", abs(main_entropy - proc_entropy)))
        
        if "matched_port" in details:
            port = details["matched_port"]
            port_entropy = self.engine.compute_entropy_score(port % 100)
            nodes[f"port_{port}"] = {
                "entropy": port_entropy,
                "node_type": "port",
                "value": port
            }
            edges.append((threat_name, f"port_{port}", abs(main_entropy - port_entropy)))
        
        return {"nodes": nodes, "edges": edges}
    
    def detect_anomalies(self, graph: Dict) -> Dict:
        """Detect anomalies in threat graph based on entropy scores."""
        nodes = graph.get("nodes", {})
        anomalies = []
        total_entropy = 0
        
        for node, attrs in nodes.items():
            entropy = attrs.get("entropy", 0)
            total_entropy += entropy
            
            if entropy > self.anomaly_threshold:
                anomalies.append({
                    "node": node,
                    "entropy": entropy,
                    "type": attrs.get("node_type", "unknown"),
                    "severity": "critical" if entropy > 0.9 else "high"
                })
        
        avg_entropy = total_entropy / max(len(nodes), 1)
        
        return {
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "average_entropy": avg_entropy,
            "risk_score": min(1.0, avg_entropy * (1 + len(anomalies) * 0.1)),
            "total_nodes": len(nodes),
            "total_edges": len(graph.get("edges", []))
        }
    
    def analyze_threat_pattern(self, threats: List[Dict]) -> Dict:
        """Analyze multiple threats to detect patterns and mutations."""
        if not threats:
            return {"patterns": [], "mutation_likelihood": 0}
        
        entropy_profiles = []
        
        for threat in threats:
            threat_graph = self.build_threat_graph(threat)
            nodes = threat_graph.get("nodes", {})
            entropies = [attrs.get("entropy", 0) for attrs in nodes.values()]
            entropy_profiles.append({
                "threat": threat.get("threat_name"),
                "mean_entropy": sum(entropies) / max(len(entropies), 1),
                "max_entropy": max(entropies) if entropies else 0
            })
        
        mean_entropies = [p["mean_entropy"] for p in entropy_profiles]
        if len(mean_entropies) > 1:
            avg = sum(mean_entropies) / len(mean_entropies)
            variance = sum((e - avg)**2 for e in mean_entropies) / len(mean_entropies)
            mutation_likelihood = min(1.0, variance * 2)
        else:
            mutation_likelihood = 0
        
        return {
            "threat_count": len(threats),
            "entropy_profiles": entropy_profiles,
            "mutation_likelihood": mutation_likelihood
        }


class EntropicNeutralizer:
    """Entropic neutralization system using chaos-based countermeasures."""
    
    def __init__(self, entropy_engine: EntropyEngine, detector: GraphAnomalyDetector):
        self.engine = entropy_engine
        self.detector = detector
        self.neutralization_log = []
        
    def calculate_threat_entropy(self, threat: Dict) -> float:
        """Calculate total entropy score for a threat."""
        graph = self.detector.build_threat_graph(threat)
        analysis = self.detector.detect_anomalies(graph)
        return analysis["risk_score"]
    
    def disintegrate_poetic(self, threat: Dict, intensity: int = 100) -> Dict:
        """Poetic mode: Conjugate inversion for entropy cancellation."""
        signature = f"{threat.get('threat_name', 'unknown')}_{threat.get('id', '')}"
        
        initial_entropy = self.calculate_threat_entropy(threat)
        flood = self.engine.generate_entropic_flood(signature, intensity)
        
        flood_entropy = flood["flood_energy"] / intensity
        entropy_delta = flood_entropy - initial_entropy
        
        success = abs(entropy_delta) < 0.3 or entropy_delta < 0
        
        result = {
            "mode": "poetic",
            "technique": "entropic_flood",
            "signature": signature,
            "initial_entropy": initial_entropy,
            "flood_energy": flood["flood_energy"],
            "entropy_delta": entropy_delta,
            "net_zero_achieved": abs(entropy_delta) < 0.1,
            "success": success,
            "flood_sample": flood["sequence_sample"][:5],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        self.neutralization_log.append(result)
        return result
    
    def disintegrate_brute(self, threat: Dict) -> Dict:
        """Brute mode: Direct entropy overwhelming."""
        signature = f"{threat.get('threat_name', 'unknown')}_{threat.get('id', '')}"
        
        initial_entropy = self.calculate_threat_entropy(threat)
        
        floods = []
        total_flood_energy = 0
        
        for i in range(3):
            mod_sig = f"{signature}_assault_{i}"
            flood = self.engine.generate_entropic_flood(mod_sig, intensity=150)
            floods.append(flood)
            total_flood_energy += flood["flood_energy"]
        
        overwhelming_ratio = total_flood_energy / max(initial_entropy * 100, 1)
        success = overwhelming_ratio > 2.0
        
        result = {
            "mode": "brute",
            "technique": "entropy_overwhelming",
            "signature": signature,
            "initial_entropy": initial_entropy,
            "total_flood_energy": total_flood_energy,
            "overwhelming_ratio": overwhelming_ratio,
            "assault_count": len(floods),
            "success": success,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        self.neutralization_log.append(result)
        return result
    
    def disintegrate(self, threat: Dict, mode: str = "poetic") -> Dict:
        """Main disintegration entry point."""
        if mode == "poetic":
            return self.disintegrate_poetic(threat)
        elif mode == "brute":
            return self.disintegrate_brute(threat)
        else:
            return self.disintegrate_poetic(threat)
    
    def get_neutralization_stats(self) -> Dict:
        """Get statistics on neutralization attempts."""
        if not self.neutralization_log:
            return {
                "total_attempts": 0,
                "success_rate": 0,
                "poetic_success": 0,
                "brute_success": 0
            }
        
        total = len(self.neutralization_log)
        successes = sum(1 for r in self.neutralization_log if r.get("success"))
        poetic = [r for r in self.neutralization_log if r.get("mode") == "poetic"]
        brute = [r for r in self.neutralization_log if r.get("mode") == "brute"]
        
        return {
            "total_attempts": total,
            "success_rate": successes / total if total > 0 else 0,
            "poetic_attempts": len(poetic),
            "poetic_success": sum(1 for r in poetic if r.get("success")),
            "brute_attempts": len(brute),
            "brute_success": sum(1 for r in brute if r.get("success")),
            "avg_entropy_delta": sum(r.get("entropy_delta", 0) for r in self.neutralization_log if "entropy_delta" in r) / max(len([r for r in self.neutralization_log if "entropy_delta" in r]), 1)
        }


# Global instances
entropy_engine = EntropyEngine()
anomaly_detector = GraphAnomalyDetector(entropy_engine)
entropic_neutralizer = EntropicNeutralizer(entropy_engine, anomaly_detector)
