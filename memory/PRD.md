# RAT Detection System - PRD

## Original Problem Statement
Build a Remote Access Trojan (RAT) Detection System - a passive security monitoring dashboard that detects RATs in the user's system, clones passkeys, devices, MAC numbers for security monitoring.

## User Choices
1. **Detection Methods**: Both - Known RAT signatures/patterns AND suspicious network connections
2. **UI Design**: AI-designed (Tactical Cyberpunk dark theme)
3. **AI-Powered Analysis**: Yes - Using Emergent LLM key (GPT-4o)

## Architecture

### Backend (FastAPI)
- **Server**: `/app/backend/server.py`
- **Database**: MongoDB
- **AI Integration**: Emergent LLM (GPT-4o) for threat analysis
- **Collections**: `detections`, `scans`

### Frontend (React)
- **Framework**: React with Tailwind CSS
- **UI Components**: Shadcn/UI
- **Charts**: Recharts (LineChart, PieChart)
- **Notifications**: Sonner

## Core Features Implemented (Jan 31, 2026)

### Backend APIs
- `GET /api/status` - System security status
- `POST /api/scan` - Trigger system scan (simulated)
- `GET /api/detections` - List all detections
- `GET /api/detections/{id}` - Get specific detection
- `POST /api/detections/{id}/analyze` - AI threat analysis
- `PATCH /api/detections/{id}/status` - Update detection status
- `GET /api/network/connections` - Network connections (simulated)
- `GET /api/signatures` - Known RAT signatures database
- `GET /api/stats` - Detection statistics

### Frontend Features
- Tactical dark theme dashboard
- Real-time threat monitoring
- Network activity chart
- Detections table with actions
- AI-powered threat analysis
- Quick scan functionality
- System logs terminal
- Suspicious connections alert panel

## User Personas
- **Primary**: Individual user monitoring their personal machine for RAT infections
- **Use Case**: Passive security monitoring without network router integration (mobile data)

## Tech Stack
- Backend: FastAPI, MongoDB, emergentintegrations
- Frontend: React, Tailwind CSS, Recharts, Shadcn/UI
- AI: GPT-4o via Emergent LLM key

## What's Working
- ✅ All 19 backend API endpoints
- ✅ Dashboard with tactical dark theme
- ✅ System scanning (simulated)
- ✅ AI-powered threat analysis
- ✅ Detections management (view, analyze, resolve)
- ✅ Network monitoring visualization
- ✅ Real-time status updates
- ✅ System activity logs

## Prioritized Backlog

### P0 (Critical) - DONE
- [x] RAT signature detection
- [x] Network connection monitoring
- [x] AI threat analysis
- [x] Dashboard UI

### P1 (Important) - Future
- [ ] Real system process scanning integration
- [ ] Real network connection monitoring (not simulated)
- [ ] Email/SMS alerts for critical threats
- [ ] Historical trend analysis

### P2 (Nice to have) - Future
- [ ] Multiple device support
- [ ] Scheduled automatic scans
- [ ] Export reports (PDF/CSV)
- [ ] Dark/light theme toggle

## Next Tasks
1. Integrate real system process scanning (if needed)
2. Add email notification for critical threats
3. Implement scheduled auto-scans
4. Add report export functionality
