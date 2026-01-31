"""
Entropy-Based Threat Detection & Neutralization Module
Based on Phi-Pi-Entropy theorem for chaos-based countermeasures

Formula: S(n) ≈ Φ · S(n-1) + (π / ln n) · e^(-n / ln(n+2))
Uses r=4.0 logistic map for conjugate inversion (entropic flood)
"""

import sympy as sp
import networkx as nx
import math
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
import random

# Theorem constants
PHI = (1 + math.sqrt(5)) / 2  # Golden ratio ≈ 1.618
PI = math.pi

class EntropyEngine:
    """
    Phi-Pi-Entropy based threat analysis and neutralization engine.
    Uses chaos theory and entropy scoring for advanced threat detection.
    """
    
    def __init__(self):
        self.entropy_cache = {}
        self.flood_history = []
        self.neutralization_count = 0
        
    def compute_entropy_score(self, n: int, s_prev: float = 1.0) -> float:
        """
        Compute entropy score using Phi-Pi-Entropy formula:
        S(n) ≈ Φ · S(n-1) + (π / ln n) · e^(-n / ln(n+2))
        
        Args:
            n: Current step/index in sequence
            s_prev: Previous entropy score (default 1.0)
            
        Returns:
            Entropy score as float
        """
        if n == 0:
            return s_prev
        
        # Avoid log(0) and log(1) issues
        n_safe = max(n, 2)
        ln_n = math.log(n_safe)
        ln_n_plus_2 = math.log(n_safe + 2)
        
        # Exponential decay term
        decay = math.exp(-n_safe / ln_n_plus_2)
        
        # Pi-scaled chaos term
        pi_term = (PI / ln_n) * decay
        
        # Phi recursive accumulation
        entropy = PHI * s_prev + pi_term
        
        # Normalize to 0-1 range with sigmoid
        normalized = 1 / (1 + math.exp(-entropy + 2))
        
        return normalized
    
    def compute_sequence_entropy(self, data: str, window_size: int = 10) -> List[float]:
        """
        Compute rolling entropy scores for a data sequence.
        
        Args:
            data: Input data string (log data, process info, etc.)
            window_size: Size of rolling window
            
        Returns:
            List of entropy scores
        """
        tokens = data.split() if isinstance(data, str) else data
        scores = []
        s_prev = 1.0
        
        for i, token in enumerate(tokens):
            # Add token hash influence
            token_hash = hash(token) % 1000 / 1000.0
            s_n = self.compute_entropy_score(i + 1, s_prev)
            
            # Blend with token-specific entropy
            blended = (s_n * 0.7) + (token_hash * 0.3)
            scores.append(blended)
            s_prev = s_n
            
        return scores
    
    def logistic_map(self, x: float, r: float = 4.0) -> float:
        """
        Logistic map function: x_n+1 = r * x_n * (1 - x_n)
        r=4.0 produces fully chaotic behavior
        """
        return r * x * (1 - x)
    
    def generate_chaos_sequence(self, seed: float, steps: int = 100) -> List[float]:
        """
        Generate chaotic sequence using r=4.0 logistic map.
        
        Args:
            seed: Initial value (0 < seed < 1)
            steps: Number of iterations
            
        Returns:
            List of chaotic values
        """
        # Ensure seed is in valid range
        x = max(0.001, min(0.999, seed))
        sequence = []
        
        for _ in range(steps):
            x = self.logistic_map(x, r=4.0)
            sequence.append(x)
            
        return sequence
    
    def conjugate_inversion(self, sequence: List[float]) -> List[float]:
        """
        Apply conjugate inversion: reverse and take complement (1 - x).
        This creates the "backward chaos flood" for entropy cancellation.
        
        Args:
            sequence: Forward chaos sequence
            
        Returns:
            Inverted sequence for neutralization
        """
        return [1 - x for x in reversed(sequence)]
    
    def generate_entropic_flood(self, signature: str, intensity: int = 100) -> Dict:
        """
        Generate entropic flood for threat neutralization.
        Uses signature hash as chaos seed, applies conjugate inversion.
        
        Args:
            signature: Threat signature (hash, name, etc.)
            intensity: Flood intensity (number of chaos iterations)
            
        Returns:
            Flood data with sequence and metrics
        """
        # Generate seed from signature hash
        sig_hash = hashlib.sha256(signature.encode()).hexdigest()
        seed = int(sig_hash[:8], 16) / (16**8)  # Normalize to 0-1
        
        # Generate forward chaos
        forward_chaos = self.generate_chaos_sequence(seed, intensity)
        
        # Apply conjugate inversion
        inverted_flood = self.conjugate_inversion(forward_chaos)
        
        # Calculate flood metrics
        flood_energy = sum(inverted_flood)
        flood_variance = sum((x - 0.5)**2 for x in inverted_flood) / len(inverted_flood)
        
        flood_data = {
            "signature": signature,
            "seed": seed,
            "intensity": intensity,
            "flood_energy": flood_energy,
            "flood_variance": flood_variance,
            "peak_amplitude": max(inverted_flood),
            "sequence_sample": inverted_flood[:10],  # First 10 values
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        self.flood_history.append(flood_data)
        return flood_data


class GraphAnomalyDetector:
    """
    Graph-based anomaly detection using entropy scoring.
    Models threats as nodes in a network with entropy-weighted edges.
    """
    
    def __init__(self, entropy_engine: EntropyEngine):
        self.engine = entropy_engine
        self.detection_graph = nx.Graph()
        self.anomaly_threshold = 0.75
        
    def build_threat_graph(self, data: Dict) -> nx.Graph:
        """
        Build a graph representation of threat data.
        Nodes represent processes/connections, edges represent relationships.
        
        Args:
            data: Threat detection data (processes, connections, behaviors)
            
        Returns:
            NetworkX graph with entropy-scored nodes
        """
        G = nx.Graph()
        
        # Extract features from threat data
        threat_name = data.get("threat_name", "unknown")
        details = data.get("details", {})
        behaviors = data.get("behavioral_profile", [])
        
        # Add main threat node
        main_entropy = self.engine.compute_entropy_score(
            hash(threat_name) % 100, 
            s_prev=0.5
        )
        G.add_node(threat_name, 
                   entropy=main_entropy, 
                   node_type="threat",
                   risk_level="high" if main_entropy > 0.7 else "medium")
        
        # Add behavior nodes
        for i, behavior in enumerate(behaviors):
            behavior_entropy = self.engine.compute_entropy_score(i + 1)
            G.add_node(f"behavior_{behavior}", 
                       entropy=behavior_entropy,
                       node_type="behavior",
                       name=behavior)
            
            # Connect to main threat
            edge_weight = abs(main_entropy - behavior_entropy)
            G.add_edge(threat_name, f"behavior_{behavior}", weight=edge_weight)
        
        # Add process node if available
        if "matched_process" in details:
            proc = details["matched_process"]
            proc_entropy = self.engine.compute_entropy_score(hash(proc) % 50)
            G.add_node(f"process_{proc}",
                       entropy=proc_entropy,
                       node_type="process",
                       name=proc)
            G.add_edge(threat_name, f"process_{proc}", 
                       weight=abs(main_entropy - proc_entropy))
        
        # Add port node if available
        if "matched_port" in details:
            port = details["matched_port"]
            port_entropy = self.engine.compute_entropy_score(port % 100)
            G.add_node(f"port_{port}",
                       entropy=port_entropy,
                       node_type="port",
                       value=port)
            G.add_edge(threat_name, f"port_{port}",
                       weight=abs(main_entropy - port_entropy))
        
        return G
    
    def detect_anomalies(self, graph: nx.Graph) -> Dict:
        """
        Detect anomalies in threat graph based on entropy scores.
        
        Args:
            graph: Threat graph with entropy-scored nodes
            
        Returns:
            Anomaly detection results
        """
        anomalies = []
        total_entropy = 0
        
        for node, attrs in graph.nodes(data=True):
            entropy = attrs.get("entropy", 0)
            total_entropy += entropy
            
            if entropy > self.anomaly_threshold:
                anomalies.append({
                    "node": node,
                    "entropy": entropy,
                    "type": attrs.get("node_type", "unknown"),
                    "severity": "critical" if entropy > 0.9 else "high"
                })
        
        # Calculate graph-level metrics
        avg_entropy = total_entropy / max(len(graph.nodes), 1)
        
        # Clustering coefficient indicates threat complexity
        try:
            clustering = nx.average_clustering(graph)
        except:
            clustering = 0
        
        return {
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "average_entropy": avg_entropy,
            "risk_score": min(1.0, avg_entropy * (1 + len(anomalies) * 0.1)),
            "complexity_score": clustering,
            "total_nodes": len(graph.nodes),
            "total_edges": len(graph.edges)
        }
    
    def analyze_threat_pattern(self, threats: List[Dict]) -> Dict:
        """
        Analyze multiple threats to detect patterns and mutations.
        
        Args:
            threats: List of threat detection data
            
        Returns:
            Pattern analysis results
        """
        if not threats:
            return {"patterns": [], "mutation_likelihood": 0}
        
        # Build combined graph
        combined_graph = nx.Graph()
        entropy_profiles = []
        
        for threat in threats:
            threat_graph = self.build_threat_graph(threat)
            combined_graph = nx.compose(combined_graph, threat_graph)
            
            # Collect entropy profile
            entropies = [attrs.get("entropy", 0) for _, attrs in threat_graph.nodes(data=True)]
            entropy_profiles.append({
                "threat": threat.get("threat_name"),
                "mean_entropy": sum(entropies) / max(len(entropies), 1),
                "max_entropy": max(entropies) if entropies else 0
            })
        
        # Detect connected components (threat clusters)
        components = list(nx.connected_components(combined_graph))
        
        # Calculate mutation likelihood based on entropy variance
        mean_entropies = [p["mean_entropy"] for p in entropy_profiles]
        if len(mean_entropies) > 1:
            variance = sum((e - sum(mean_entropies)/len(mean_entropies))**2 
                          for e in mean_entropies) / len(mean_entropies)
            mutation_likelihood = min(1.0, variance * 2)
        else:
            mutation_likelihood = 0
        
        return {
            "threat_count": len(threats),
            "cluster_count": len(components),
            "entropy_profiles": entropy_profiles,
            "mutation_likelihood": mutation_likelihood,
            "pattern_complexity": len(combined_graph.edges) / max(len(combined_graph.nodes), 1)
        }


class EntropicNeutralizer:
    """
    Entropic neutralization system using chaos-based countermeasures.
    Implements the "disintegrate" functionality with poetic and brute modes.
    """
    
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
        """
        Poetic mode disintegration: Entropic flood approach.
        Uses conjugate inversion to cancel threat entropy.
        
        Args:
            threat: Threat data to neutralize
            intensity: Flood intensity
            
        Returns:
            Disintegration results
        """
        signature = f"{threat.get('threat_name', 'unknown')}_{threat.get('id', '')}"
        
        # Calculate initial threat entropy
        initial_entropy = self.calculate_threat_entropy(threat)
        
        # Generate entropic flood
        flood = self.engine.generate_entropic_flood(signature, intensity)
        
        # Calculate entropy delta (goal: net-zero)
        flood_entropy = flood["flood_energy"] / intensity  # Normalize
        entropy_delta = flood_entropy - initial_entropy
        
        # Determine success based on entropy cancellation
        # Success if delta is close to zero or negative (entropy reduced)
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
        """
        Brute mode disintegration: Direct entropy overwhelming.
        Applies maximum chaos to disrupt threat patterns.
        
        Args:
            threat: Threat data to neutralize
            
        Returns:
            Disintegration results
        """
        signature = f"{threat.get('threat_name', 'unknown')}_{threat.get('id', '')}"
        
        # Calculate initial threat entropy
        initial_entropy = self.calculate_threat_entropy(threat)
        
        # Generate multiple high-intensity floods
        floods = []
        total_flood_energy = 0
        
        for i in range(3):  # Triple flood assault
            mod_sig = f"{signature}_assault_{i}"
            flood = self.engine.generate_entropic_flood(mod_sig, intensity=150)
            floods.append(flood)
            total_flood_energy += flood["flood_energy"]
        
        # Brute force success based on overwhelming the threat entropy
        overwhelming_ratio = total_flood_energy / max(initial_entropy * 100, 1)
        success = overwhelming_ratio > 2.0  # Need 2x entropy to overwhelm
        
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
        """
        Main disintegration entry point.
        
        Args:
            threat: Threat data to neutralize
            mode: "poetic" (entropic flood) or "brute" (overwhelming)
            
        Returns:
            Disintegration results
        """
        if mode == "poetic":
            return self.disintegrate_poetic(threat)
        elif mode == "brute":
            return self.disintegrate_brute(threat)
        else:
            # Default to poetic
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


# Global instances for use in server
entropy_engine = EntropyEngine()
anomaly_detector = GraphAnomalyDetector(entropy_engine)
entropic_neutralizer = EntropicNeutralizer(entropy_engine, anomaly_detector)
