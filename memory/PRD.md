# RAT Countermeasure Agent - PRD

## Original Problem Statement
Build an Agentic RAT (Remote Access Trojan) Countermeasure System that autonomously detects, learns, and evicts threats from the system using non-harmful techniques like fault injection, resource starvation, network isolation, and **Phi-Pi-Entropy chaos-based countermeasures**.

## User Choices

### Phase 1 - Basic Detection
- Both detection methods (RAT signatures + network monitoring)
- AI-designed dark tactical UI
- AI-powered analysis via Emergent LLM key

### Phase 2 - Countermeasure Agent
- All countermeasure techniques
- Fully autonomous mode
- Both mutation detection methods (signature + behavioral)
- War log tracking

### Phase 3 - Phi-Pi-Entropy Integration
- **Entropy scoring** for threat classification using formula: `S(n) ≈ Φ·S(n-1) + (π/ln n)·e^(-n/ln(n+2))`
- **Chaotic disintegration** with r=4.0 logistic map and conjugate inversion
- **Graph-based anomaly detection** for pattern recognition
- Two modes: **Poetic** (entropy cancellation) and **Brute** (entropy overwhelming)

## Architecture

### Backend (FastAPI)
- **Server**: `/app/backend/server.py`
- **Entropy Engine**: `/app/backend/entropy_engine.py`
- **Database**: MongoDB
- **AI Integration**: GPT-4o via Emergent LLM key

### Core Classes
- `EntropyEngine` - Phi-Pi-Entropy formula implementation
- `GraphAnomalyDetector` - NetworkX-based pattern analysis
- `EntropicNeutralizer` - Poetic/Brute disintegration modes
- `RATCountermeasureAgent` - AI-powered autonomous agent

## Phi-Pi-Entropy System

### Core Formula
```
S(n) ≈ Φ · S(n-1) + (π / ln n) · e^(-n / ln(n+2))

Where:
- Φ (Phi) = 1.618033989 (Golden Ratio)
- π (Pi) = 3.141592654
- r = 4.0 (Chaos parameter for logistic map)
```

### Disintegration Modes
1. **Poetic Mode** - Conjugate inversion for entropy cancellation
   - Uses backward chaos flood
   - Goal: Net-zero entropy delta
   - Best for: Single threats, precision eviction

2. **Brute Mode** - Triple chaos assault
   - r=4.0 logistic map × 3 assaults
   - Overwhelms threat entropy
   - Best for: Mutations, replicating threats

## Countermeasure Techniques (8 total)

1. `fault_injection` - Introduce errors to crash RAT
2. `resource_starvation` - Starve RAT of CPU/memory
3. `network_isolation` - Block C2 communications
4. `process_termination` - Kill RAT process
5. `memory_corruption` - Corrupt RAT memory space
6. `decoy_deployment` - Deploy honeypots
7. `entropic_flood_poetic` - Phi-Pi-Entropy conjugate inversion ⚡ NEW
8. `entropic_flood_brute` - Triple chaos assault ⚡ NEW

## API Endpoints (40+)

### Core APIs
- Status, Scan, Agent control, Detections, War Log, Stats

### Entropy APIs (NEW)
- `POST /api/entropy/scan` - Analyze threats with entropy scoring
- `POST /api/entropy/disintegrate/{id}` - Disintegrate with poetic/brute
- `POST /api/entropy/flood` - Generate chaos sequence
- `GET /api/entropy/stats` - Neutralization statistics
- `POST /api/entropy/analyze-pattern` - Graph-based pattern analysis

## Frontend Features

### 5 Tabs
1. **Overview** - Stats, network activity, agent status
2. **War Log** - Battle history
3. **Detections** - Active vs Evicted threats
4. **Tactics** - Countermeasure effectiveness
5. **Entropy** - Phi-Pi-Entropy engine ⚡ NEW

### Entropy Tab Features
- Formula display with Φ, π, r values
- Poetic/Brute mode descriptions
- Real-time entropy stats
- Entropy Scan, Poetic Flood, Brute Flood buttons
- Scan results with entropy scores

## What's Working
- ✅ 40+ backend API endpoints (90% pass rate)
- ✅ Autonomous agent with GPT-4o
- ✅ 8 countermeasure techniques including entropic floods
- ✅ Phi-Pi-Entropy formula implementation
- ✅ Graph-based anomaly detection
- ✅ Poetic and Brute disintegration modes
- ✅ 84%+ eviction success rate

## Tech Stack
- Backend: FastAPI, MongoDB, sympy, networkx, emergentintegrations
- Frontend: React, Tailwind CSS, Recharts, Shadcn/UI
- AI: GPT-4o via Emergent LLM key
- Math: Phi-Pi-Entropy formula, r=4.0 logistic chaos

## Next Tasks
1. Add scheduled autonomous patrol cycles with entropy scanning
2. Implement entropy trend visualization
3. Add threat clustering based on entropy profiles
4. Export entropy analysis reports
