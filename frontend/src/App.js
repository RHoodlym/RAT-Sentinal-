import { useState, useEffect, useCallback } from "react";
import "@/App.css";
import axios from "axios";
import { Toaster, toast } from "sonner";
import { 
  ShieldAlert, 
  Activity, 
  Network, 
  Terminal, 
  Scan,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  Cpu,
  Wifi,
  Eye,
  Zap,
  Crosshair,
  Bot,
  Swords,
  BookOpen,
  Target,
  Shield,
  Skull,
  Brain,
  TrendingUp,
  Flame,
  Atom,
  Waves
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar
} from "recharts";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Stat Card Component
const StatCard = ({ title, value, icon: Icon, status, subtitle, glow }) => {
  const statusColors = {
    safe: "text-emerald-500",
    warning: "text-amber-500",
    danger: "text-red-500",
    critical: "text-red-600",
    neutral: "text-zinc-400",
    purple: "text-purple-500",
    cyan: "text-cyan-500"
  };

  return (
    <div className={`stat-card ${glow ? 'threat-glow' : ''}`} data-testid={`stat-card-${title.toLowerCase().replace(/\s+/g, '-')}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs uppercase tracking-wider text-zinc-500 font-mono">{title}</p>
          <p className={`text-3xl font-bold mt-1 ${statusColors[status] || 'text-white'}`}>
            {value}
          </p>
          {subtitle && <p className="text-xs text-zinc-500 mt-1">{subtitle}</p>}
        </div>
        <div className={`p-2 rounded ${status === 'danger' || status === 'critical' ? 'bg-red-500/20' : status === 'warning' ? 'bg-amber-500/20' : status === 'safe' ? 'bg-emerald-500/20' : 'bg-zinc-800'}`}>
          <Icon className={`w-5 h-5 ${statusColors[status] || 'text-zinc-400'}`} />
        </div>
      </div>
    </div>
  );
};

// War Log Entry Component
const WarLogEntry = ({ entry }) => {
  const typeIcons = {
    detection: <AlertTriangle className="w-3 h-3 text-red-500" />,
    analysis: <Brain className="w-3 h-3 text-blue-500" />,
    countermeasure: <Crosshair className="w-3 h-3 text-amber-500" />,
    mutation: <Skull className="w-3 h-3 text-purple-500" />,
    eviction: <CheckCircle className="w-3 h-3 text-emerald-500" />,
    escalation: <Zap className="w-3 h-3 text-orange-500" />,
    learning: <BookOpen className="w-3 h-3 text-cyan-500" />
  };

  const typeColors = {
    detection: "border-l-red-500 bg-red-500/5",
    analysis: "border-l-blue-500 bg-blue-500/5",
    countermeasure: "border-l-amber-500 bg-amber-500/5",
    mutation: "border-l-purple-500 bg-purple-500/5",
    eviction: "border-l-emerald-500 bg-emerald-500/5",
    escalation: "border-l-orange-500 bg-orange-500/5",
    learning: "border-l-cyan-500 bg-cyan-500/5"
  };

  const timestamp = new Date(entry.timestamp).toLocaleTimeString('en-US', { hour12: false });

  return (
    <div className={`p-3 border-l-2 mb-2 ${typeColors[entry.event_type] || 'border-l-zinc-500'}`} data-testid={`war-log-${entry.id}`}>
      <div className="flex items-start gap-2">
        {typeIcons[entry.event_type]}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono text-zinc-500">[{timestamp}]</span>
            <Badge variant="outline" className="text-[10px] uppercase">{entry.event_type}</Badge>
            {entry.outcome && (
              <Badge className={entry.outcome === 'SUCCESS' || entry.outcome === 'EVICTED' ? 'badge-safe' : 'badge-danger'}>
                {entry.outcome}
              </Badge>
            )}
          </div>
          <p className="text-sm text-zinc-300">{entry.description}</p>
          {entry.ai_decision && (
            <p className="text-xs text-zinc-500 mt-1 italic">AI: {entry.ai_decision}</p>
          )}
          {entry.tactics_learned && entry.tactics_learned.length > 0 && (
            <div className="flex gap-1 mt-1 flex-wrap">
              {entry.tactics_learned.map((tactic, i) => (
                <Badge key={i} variant="outline" className="text-[10px] text-cyan-400 border-cyan-400/50">
                  {tactic}
                </Badge>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Detection Row Component
const DetectionRow = ({ detection, onAnalyze, isAnalyzing }) => {
  const severityColors = {
    critical: "badge-danger",
    high: "bg-orange-500/20 text-orange-500 border border-orange-500/50",
    medium: "badge-warning",
    low: "badge-safe"
  };

  const statusColors = {
    active: "badge-danger",
    evicted: "badge-safe",
    resolved: "bg-blue-500/20 text-blue-500 border border-blue-500/50",
    false_positive: "badge-neutral"
  };

  return (
    <tr data-testid={`detection-row-${detection.id}`}>
      <td className="font-mono text-xs">
        {detection.threat_name}
        {detection.mutation_detected && (
          <Badge className="ml-2 bg-purple-500/20 text-purple-400 text-[10px]">MUTANT</Badge>
        )}
      </td>
      <td>
        <span className={`inline-block px-2 py-0.5 text-xs rounded ${severityColors[detection.severity]}`}>
          {detection.severity}
        </span>
      </td>
      <td className="text-zinc-400 text-xs">{detection.detection_type?.replace('_', ' ')}</td>
      <td>
        <span className={`inline-block px-2 py-0.5 text-xs rounded ${statusColors[detection.status]}`}>
          {detection.status}
        </span>
      </td>
      <td className="text-right">
        <Button 
          variant="ghost" 
          size="sm"
          onClick={() => onAnalyze(detection.id)}
          disabled={isAnalyzing || detection.status === 'evicted'}
          data-testid={`analyze-btn-${detection.id}`}
          className="text-xs hover:bg-emerald-500/20 hover:text-emerald-500"
        >
          <Eye className="w-3 h-3 mr-1" />
          Analyze
        </Button>
      </td>
    </tr>
  );
};

// Countermeasure Card
const CountermeasureCard = ({ technique, data }) => {
  const successRate = data.total > 0 ? ((data.success / data.total) * 100).toFixed(0) : 0;
  
  return (
    <div className="p-3 bg-zinc-900/50 border border-zinc-800 rounded" data-testid={`cm-card-${technique}`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-mono uppercase text-zinc-400">{technique.replace('_', ' ')}</span>
        <Badge className={successRate >= 70 ? 'badge-safe' : successRate >= 40 ? 'badge-warning' : 'badge-danger'}>
          {successRate}%
        </Badge>
      </div>
      <div className="flex items-center gap-2 text-xs text-zinc-500">
        <span>{data.total} deployed</span>
        <span>•</span>
        <span className="text-emerald-500">{data.success} success</span>
      </div>
    </div>
  );
};

// Main Dashboard
function App() {
  const [systemStatus, setSystemStatus] = useState(null);
  const [detections, setDetections] = useState([]);
  const [warLog, setWarLog] = useState([]);
  const [stats, setStats] = useState(null);
  const [agentState, setAgentState] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isAgentRunning, setIsAgentRunning] = useState(false);
  const [networkData, setNetworkData] = useState([]);
  const [activeTab, setActiveTab] = useState("overview");
  const [entropyStats, setEntropyStats] = useState(null);
  const [entropyScanResults, setEntropyScanResults] = useState(null);

  // Fetch entropy stats
  const fetchEntropyStats = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/entropy/stats`);
      setEntropyStats(response.data);
    } catch (e) {
      console.error("Failed to fetch entropy stats:", e);
    }
  }, []);

  // Run entropy scan
  const runEntropyScan = async () => {
    setIsScanning(true);
    toast.info('Entropy Scan', { description: 'Running entropy analysis...' });
    try {
      const response = await axios.post(`${API}/entropy/scan`);
      setEntropyScanResults(response.data);
      toast.success('Entropy Scan Complete', { 
        description: `Analyzed ${response.data.threat_count || 0} threats` 
      });
      await fetchEntropyStats();
    } catch (e) {
      toast.error('Entropy Scan Failed', { description: e.message });
    } finally {
      setIsScanning(false);
    }
  };

  // Run poetic flood on all active threats
  const runPoeticFlood = async () => {
    const active = detections.filter(d => d.status === 'active');
    if (active.length === 0) {
      toast.info('No Targets', { description: 'No active threats to neutralize' });
      return;
    }
    
    setIsScanning(true);
    toast.info('Poetic Flood', { description: 'Deploying conjugate inversion...' });
    
    let evicted = 0;
    for (const threat of active.slice(0, 5)) { // Process up to 5
      try {
        const response = await axios.post(`${API}/entropy/disintegrate/${threat.id}?mode=poetic`);
        if (response.data.result?.success) evicted++;
      } catch (e) {
        console.error(`Failed to disintegrate ${threat.id}:`, e);
      }
    }
    
    toast.success('Poetic Flood Complete', { 
      description: `Evicted ${evicted}/${Math.min(active.length, 5)} threats` 
    });
    
    await Promise.all([fetchDetections(), fetchWarLog(), fetchEntropyStats()]);
    setIsScanning(false);
  };

  // Run brute flood on all active threats
  const runBruteFlood = async () => {
    const active = detections.filter(d => d.status === 'active');
    if (active.length === 0) {
      toast.info('No Targets', { description: 'No active threats to neutralize' });
      return;
    }
    
    setIsScanning(true);
    toast.info('Brute Flood', { description: 'Deploying triple chaos assault...' });
    
    let evicted = 0;
    for (const threat of active.slice(0, 5)) { // Process up to 5
      try {
        const response = await axios.post(`${API}/entropy/disintegrate/${threat.id}?mode=brute`);
        if (response.data.result?.success) evicted++;
      } catch (e) {
        console.error(`Failed to disintegrate ${threat.id}:`, e);
      }
    }
    
    toast.success('Brute Flood Complete', { 
      description: `Evicted ${evicted}/${Math.min(active.length, 5)} threats` 
    });
    
    await Promise.all([fetchDetections(), fetchWarLog(), fetchEntropyStats()]);
    setIsScanning(false);
  };

  // Fetch patrol status
  const [patrolStatus, setPatrolStatus] = useState(null);
  
  const fetchPatrolStatus = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/patrol/status`);
      setPatrolStatus(response.data);
    } catch (e) {
      console.error("Failed to fetch patrol status:", e);
    }
  }, []);

  // Fetch all data
  const fetchStatus = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/status`);
      setSystemStatus(response.data);
      setAgentState(response.data.agent_state);
    } catch (e) {
      console.error("Failed to fetch status:", e);
    }
  }, []);

  const fetchDetections = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/detections?limit=50`);
      setDetections(response.data);
    } catch (e) {
      console.error("Failed to fetch detections:", e);
    }
  }, []);

  const fetchWarLog = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/war-log?limit=50`);
      setWarLog(response.data);
    } catch (e) {
      console.error("Failed to fetch war log:", e);
    }
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/stats`);
      setStats(response.data);
    } catch (e) {
      console.error("Failed to fetch stats:", e);
    }
  }, []);

  const fetchConnections = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/network/connections`);
      const suspicious = response.data.filter(c => c.is_suspicious).length;
      
      setNetworkData(prev => {
        const newData = [...prev, {
          time: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
          connections: response.data.length,
          suspicious: suspicious,
          blocked: response.data.filter(c => c.blocked).length
        }].slice(-20);
        return newData;
      });
    } catch (e) {
      console.error("Failed to fetch connections:", e);
    }
  }, []);

  // Start scan
  const startScan = async () => {
    setIsScanning(true);
    setScanProgress(0);
    toast.info('Scan initiated', { description: 'Scanning for threats...' });

    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 95) {
          clearInterval(progressInterval);
          return prev;
        }
        return prev + Math.random() * 15;
      });
    }, 200);

    try {
      const response = await axios.post(`${API}/system/scan`);
      clearInterval(progressInterval);
      setScanProgress(100);
      
      if (response.data.threats_found > 0) {
        toast.error('Threats Detected!', { 
          description: `Found ${response.data.threats_found} threat(s) - Agent engaging...` 
        });
      } else {
        toast.success('Scan Complete', { description: 'No threats detected' });
      }

      // Refresh all data
      await Promise.all([fetchStatus(), fetchDetections(), fetchWarLog(), fetchStats()]);
    } catch (e) {
      clearInterval(progressInterval);
      toast.error('Scan Failed', { description: e.message });
    } finally {
      setIsScanning(false);
      setScanProgress(0);
    }
  };

  // Trigger agent manually
  const triggerAgent = async () => {
    setIsAgentRunning(true);
    toast.info('Agent Activated', { description: 'Running countermeasure cycle...' });

    try {
      const response = await axios.post(`${API}/agent/run`);
      
      if (response.data.evicted > 0) {
        toast.success('Threats Evicted!', { 
          description: `Successfully evicted ${response.data.evicted} threat(s)` 
        });
      } else if (response.data.threats_processed > 0) {
        toast.warning('Agent Cycle Complete', { 
          description: `Processed ${response.data.threats_processed} threats` 
        });
      } else {
        toast.info('All Clear', { description: 'No active threats to process' });
      }

      await Promise.all([fetchStatus(), fetchDetections(), fetchWarLog(), fetchStats()]);
    } catch (e) {
      toast.error('Agent Error', { description: e.message });
    } finally {
      setIsAgentRunning(false);
    }
  };

  // AI Analysis
  const analyzeDetection = async (detectionId) => {
    setIsAnalyzing(true);
    toast.info('AI Analysis', { description: 'Analyzing threat...' });

    try {
      const response = await axios.post(`${API}/detections/${detectionId}/analyze`);
      toast.success('Analysis Complete', { 
        description: `Strategy: ${response.data.strategy?.primary_technique || 'determined'}` 
      });
      await fetchDetections();
    } catch (e) {
      toast.error('Analysis Failed', { description: e.message });
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Initial load and polling
  useEffect(() => {
    fetchStatus();
    fetchDetections();
    fetchWarLog();
    fetchStats();
    fetchConnections();
    fetchEntropyStats();
    fetchPatrolStatus();

    const interval = setInterval(() => {
      fetchStatus();
      fetchWarLog();
      fetchConnections();
      fetchPatrolStatus();
    }, 5000);  // Faster polling for real-time feel

    return () => clearInterval(interval);
  }, [fetchStatus, fetchDetections, fetchWarLog, fetchStats, fetchConnections, fetchEntropyStats, fetchPatrolStatus]);

  // Chart data
  const techniqueData = stats?.by_technique ? Object.entries(stats.by_technique).map(([name, data]) => ({
    name: name.replace('_', ' ').slice(0, 10),
    success: data.success,
    failed: data.total - data.success
  })) : [];

  const activeThreats = detections.filter(d => d.status === 'active');
  const evictedThreats = detections.filter(d => d.status === 'evicted');

  return (
    <div className="App min-h-screen bg-[#09090B]" data-testid="rat-countermeasure-dashboard">
      <Toaster position="top-right" theme="dark" />
      <div className="noise-overlay" />
      
      {/* Patrol Status Banner */}
      {patrolStatus?.is_running && (
        <div className="bg-emerald-500/10 border-b border-emerald-500/30 px-4 py-2">
          <div className="container mx-auto flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
              <span className="text-xs font-mono text-emerald-400">AUTONOMOUS PATROL ACTIVE</span>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono text-zinc-400">
              <span>Cycle: {patrolStatus?.cycle_count || 0}</span>
              <span>Neutralized: <span className="text-emerald-400">{patrolStatus?.threats_neutralized || 0}</span></span>
              <span>Countermeasures: {patrolStatus?.total_countermeasures || 0}</span>
              {patrolStatus?.active_escalations > 0 && (
                <span className="text-amber-400">Escalating: {patrolStatus?.active_escalations}</span>
              )}
            </div>
          </div>
        </div>
      )}
      
      {/* Header */}
      <header className="border-b border-white/10 bg-black/40 backdrop-blur-md sticky top-0 z-50">
        <div className="container mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded ${systemStatus?.active_threats > 0 ? 'bg-red-500/20 threat-glow' : 'bg-emerald-500/20'}`}>
              <Swords className={`w-6 h-6 ${systemStatus?.active_threats > 0 ? 'text-red-500' : 'text-emerald-500'}`} />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight" data-testid="app-title">
                RAT COUNTERMEASURE AGENT
              </h1>
              <p className="text-xs text-zinc-500 font-mono">v2.0 // AUTONOMOUS MODE</p>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            {/* Agent Status */}
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded border ${
              agentState?.is_active ? 'bg-emerald-500/10 border-emerald-500/50' : 'bg-zinc-800 border-zinc-700'
            }`} data-testid="agent-status">
              <Bot className={`w-4 h-4 ${agentState?.is_active ? 'text-emerald-500' : 'text-zinc-500'}`} />
              <span className="text-xs font-mono uppercase">
                {agentState?.mode || 'AUTONOMOUS'}
              </span>
            </div>

            {/* Threat Level */}
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded ${
              systemStatus?.threat_level === 'critical' ? 'bg-red-500/20 border border-red-500/50 threat-glow' :
              systemStatus?.threat_level === 'danger' ? 'bg-red-500/20 border border-red-500/50' :
              systemStatus?.threat_level === 'warning' ? 'bg-amber-500/20 border border-amber-500/50' :
              'bg-emerald-500/20 border border-emerald-500/50'
            }`} data-testid="threat-level">
              <div className={`w-2 h-2 rounded-full ${
                systemStatus?.threat_level === 'critical' || systemStatus?.threat_level === 'danger' ? 'bg-red-500 blink' :
                systemStatus?.threat_level === 'warning' ? 'bg-amber-500' :
                'bg-emerald-500'
              }`} />
              <span className={`text-xs font-mono uppercase ${
                systemStatus?.threat_level === 'critical' || systemStatus?.threat_level === 'danger' ? 'text-red-500' :
                systemStatus?.threat_level === 'warning' ? 'text-amber-500' :
                'text-emerald-500'
              }`}>
                {systemStatus?.threat_level || 'SAFE'}
              </span>
            </div>

            {/* Action Buttons */}
            <Button
              onClick={triggerAgent}
              disabled={isAgentRunning || isScanning}
              data-testid="trigger-agent-btn"
              className="bg-purple-600 hover:bg-purple-700 text-white font-mono text-xs uppercase"
            >
              {isAgentRunning ? (
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Crosshair className="w-4 h-4 mr-2" />
              )}
              ENGAGE
            </Button>

            <Button
              onClick={startScan}
              disabled={isScanning || isAgentRunning}
              data-testid="scan-btn"
              className="bg-emerald-600 hover:bg-emerald-700 text-white font-mono text-xs uppercase"
            >
              {isScanning ? (
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Scan className="w-4 h-4 mr-2" />
              )}
              SCAN
            </Button>
          </div>
        </div>

        {/* Progress Bar */}
        {(isScanning || isAgentRunning) && (
          <div className="px-4 pb-3">
            <Progress value={isScanning ? scanProgress : 50} className="h-1 bg-zinc-800" />
            <p className="text-xs font-mono text-zinc-500 mt-1">
              {isScanning ? 'Scanning system...' : 'Agent processing threats...'}
            </p>
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-6">
        {/* Stats Row */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          <StatCard
            title="Active Threats"
            value={systemStatus?.active_threats || 0}
            icon={AlertTriangle}
            status={systemStatus?.active_threats > 0 ? 'danger' : 'safe'}
            subtitle="Requires action"
            glow={systemStatus?.active_threats > 0}
          />
          <StatCard
            title="Evicted"
            value={systemStatus?.evicted_threats || 0}
            icon={Shield}
            status="safe"
            subtitle="Successfully removed"
          />
          <StatCard
            title="Mutations"
            value={systemStatus?.mutations_detected || 0}
            icon={Skull}
            status={systemStatus?.mutations_detected > 0 ? 'purple' : 'neutral'}
            subtitle="Variants detected"
          />
          <StatCard
            title="Countermeasures"
            value={systemStatus?.countermeasures_deployed || 0}
            icon={Crosshair}
            status="warning"
            subtitle="Actions taken"
          />
          <StatCard
            title="Success Rate"
            value={`${stats?.success_rate?.toFixed(0) || 0}%`}
            icon={TrendingUp}
            status={stats?.success_rate >= 70 ? 'safe' : stats?.success_rate >= 40 ? 'warning' : 'danger'}
            subtitle="Eviction rate"
          />
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="bg-zinc-900 border border-zinc-800">
            <TabsTrigger value="overview" className="font-mono text-xs" data-testid="tab-overview">
              <Activity className="w-3 h-3 mr-1" /> Overview
            </TabsTrigger>
            <TabsTrigger value="warlog" className="font-mono text-xs" data-testid="tab-warlog">
              <BookOpen className="w-3 h-3 mr-1" /> War Log
            </TabsTrigger>
            <TabsTrigger value="detections" className="font-mono text-xs" data-testid="tab-detections">
              <Target className="w-3 h-3 mr-1" /> Detections
            </TabsTrigger>
            <TabsTrigger value="tactics" className="font-mono text-xs" data-testid="tab-tactics">
              <Brain className="w-3 h-3 mr-1" /> Tactics
            </TabsTrigger>
            <TabsTrigger value="entropy" className="font-mono text-xs" data-testid="tab-entropy">
              <Atom className="w-3 h-3 mr-1" /> Entropy
            </TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Network Activity */}
              <div className="lg:col-span-2 card-tactical p-4" data-testid="network-chart">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Network className="w-4 h-4 text-emerald-500" />
                    <h2 className="text-sm font-bold uppercase tracking-wider">Network Activity</h2>
                  </div>
                </div>
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={networkData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#27272A" />
                      <XAxis dataKey="time" stroke="#71717A" fontSize={10} />
                      <YAxis stroke="#71717A" fontSize={10} />
                      <Tooltip contentStyle={{ background: '#18181B', border: '1px solid #27272A', fontSize: '12px' }} />
                      <Line type="monotone" dataKey="connections" stroke="#10B981" strokeWidth={2} dot={false} name="Total" />
                      <Line type="monotone" dataKey="suspicious" stroke="#EF4444" strokeWidth={2} dot={false} name="Suspicious" />
                      <Line type="monotone" dataKey="blocked" stroke="#8B5CF6" strokeWidth={2} dot={false} name="Blocked" />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Agent Stats */}
              <div className="card-tactical p-4" data-testid="agent-stats">
                <div className="flex items-center gap-2 mb-4">
                  <Bot className="w-4 h-4 text-purple-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider">Agent Status</h2>
                </div>
                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-zinc-500">Mode</span>
                    <Badge className="bg-purple-500/20 text-purple-400">{agentState?.mode || 'AUTONOMOUS'}</Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-zinc-500">Learning Iterations</span>
                    <span className="font-mono text-cyan-400">{agentState?.learning_iterations || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-zinc-500">Tactics Learned</span>
                    <span className="font-mono text-cyan-400">{stats?.agent_tactics_learned || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-zinc-500">Last Action</span>
                    <span className="font-mono text-xs text-zinc-400 truncate max-w-[150px]">
                      {agentState?.last_action || 'Idle'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Recent War Log Preview */}
            <div className="card-tactical p-4" data-testid="recent-warlog">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Swords className="w-4 h-4 text-amber-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider">Recent Battle Activity</h2>
                </div>
                <Button variant="ghost" size="sm" onClick={() => setActiveTab('warlog')} className="text-xs">
                  View All
                </Button>
              </div>
              <ScrollArea className="h-64">
                {warLog.slice(0, 10).map(entry => (
                  <WarLogEntry key={entry.id} entry={entry} />
                ))}
                {warLog.length === 0 && (
                  <div className="flex flex-col items-center justify-center py-8 text-zinc-500">
                    <Shield className="w-8 h-8 mb-2 text-emerald-500/50" />
                    <p className="text-sm font-mono">No battle activity yet</p>
                  </div>
                )}
              </ScrollArea>
            </div>
          </TabsContent>

          {/* War Log Tab */}
          <TabsContent value="warlog" className="space-y-6">
            <div className="card-tactical p-4" data-testid="full-warlog">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <BookOpen className="w-4 h-4 text-amber-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider">Complete War Log</h2>
                </div>
                <Badge variant="outline" className="font-mono text-xs">
                  {warLog.length} entries
                </Badge>
              </div>
              <ScrollArea className="h-[600px]">
                {warLog.map(entry => (
                  <WarLogEntry key={entry.id} entry={entry} />
                ))}
                {warLog.length === 0 && (
                  <div className="flex flex-col items-center justify-center py-12 text-zinc-500">
                    <Shield className="w-12 h-12 mb-3 text-emerald-500/50" />
                    <p className="font-mono">No battle history</p>
                    <p className="text-xs mt-1">Run a scan to detect threats</p>
                  </div>
                )}
              </ScrollArea>
            </div>
          </TabsContent>

          {/* Detections Tab */}
          <TabsContent value="detections" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Active Threats */}
              <div className="card-tactical p-4" data-testid="active-threats">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-red-500" />
                    <h2 className="text-sm font-bold uppercase tracking-wider">Active Threats</h2>
                  </div>
                  <Badge className="badge-danger">{activeThreats.length}</Badge>
                </div>
                <ScrollArea className="h-80">
                  {activeThreats.length > 0 ? (
                    <table className="detection-table">
                      <thead>
                        <tr>
                          <th>Threat</th>
                          <th>Severity</th>
                          <th>Type</th>
                          <th>Status</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        {activeThreats.map(detection => (
                          <DetectionRow
                            key={detection.id}
                            detection={detection}
                            onAnalyze={analyzeDetection}
                            isAnalyzing={isAnalyzing}
                          />
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-12 text-zinc-500">
                      <CheckCircle className="w-12 h-12 mb-3 text-emerald-500/50" />
                      <p className="font-mono">No active threats</p>
                    </div>
                  )}
                </ScrollArea>
              </div>

              {/* Evicted Threats */}
              <div className="card-tactical p-4" data-testid="evicted-threats">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-emerald-500" />
                    <h2 className="text-sm font-bold uppercase tracking-wider">Evicted Threats</h2>
                  </div>
                  <Badge className="badge-safe">{evictedThreats.length}</Badge>
                </div>
                <ScrollArea className="h-80">
                  {evictedThreats.length > 0 ? (
                    <table className="detection-table">
                      <thead>
                        <tr>
                          <th>Threat</th>
                          <th>Severity</th>
                          <th>Type</th>
                          <th>Status</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        {evictedThreats.map(detection => (
                          <DetectionRow
                            key={detection.id}
                            detection={detection}
                            onAnalyze={analyzeDetection}
                            isAnalyzing={isAnalyzing}
                          />
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-12 text-zinc-500">
                      <Target className="w-12 h-12 mb-3 text-zinc-700" />
                      <p className="font-mono">No evictions yet</p>
                    </div>
                  )}
                </ScrollArea>
              </div>
            </div>
          </TabsContent>

          {/* Tactics Tab */}
          <TabsContent value="tactics" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Countermeasure Effectiveness */}
              <div className="card-tactical p-4" data-testid="cm-effectiveness">
                <div className="flex items-center gap-2 mb-4">
                  <Crosshair className="w-4 h-4 text-amber-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider">Countermeasure Effectiveness</h2>
                </div>
                {techniqueData.length > 0 ? (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={techniqueData} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" stroke="#27272A" />
                        <XAxis type="number" stroke="#71717A" fontSize={10} />
                        <YAxis dataKey="name" type="category" stroke="#71717A" fontSize={10} width={80} />
                        <Tooltip contentStyle={{ background: '#18181B', border: '1px solid #27272A', fontSize: '12px' }} />
                        <Bar dataKey="success" stackId="a" fill="#10B981" name="Success" />
                        <Bar dataKey="failed" stackId="a" fill="#EF4444" name="Failed" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-12 text-zinc-500">
                    <Brain className="w-12 h-12 mb-3 text-zinc-700" />
                    <p className="font-mono">No tactics data yet</p>
                  </div>
                )}
              </div>

              {/* Technique Cards */}
              <div className="card-tactical p-4" data-testid="technique-cards">
                <div className="flex items-center gap-2 mb-4">
                  <Brain className="w-4 h-4 text-cyan-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider">Techniques by Success</h2>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  {stats?.by_technique && Object.entries(stats.by_technique).map(([technique, data]) => (
                    <CountermeasureCard key={technique} technique={technique} data={data} />
                  ))}
                  {(!stats?.by_technique || Object.keys(stats.by_technique).length === 0) && (
                    <div className="col-span-2 flex flex-col items-center justify-center py-8 text-zinc-500">
                      <Crosshair className="w-8 h-8 mb-2 text-zinc-700" />
                      <p className="font-mono text-sm">No techniques deployed</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </TabsContent>

          {/* Entropy Tab */}
          <TabsContent value="entropy" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Entropy Formula Display */}
              <div className="lg:col-span-2 card-tactical p-4 border-cyan-500/30" data-testid="entropy-engine">
                <div className="flex items-center gap-2 mb-4">
                  <Atom className="w-4 h-4 text-cyan-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider">Phi-Pi-Entropy Engine</h2>
                </div>
                <div className="bg-black/50 p-4 rounded border border-cyan-500/20 mb-4">
                  <p className="font-mono text-cyan-400 text-sm mb-2">Core Formula:</p>
                  <p className="font-mono text-lg text-white">[ENTROPY ENGINE ACTIVE]</p>
                  <div className="grid grid-cols-3 gap-4 mt-4 text-xs">
                    <div>
                      <span className="text-zinc-500">Coefficient α</span>
                      <p className="font-mono text-amber-400">[CLASSIFIED]</p>
                    </div>
                    <div>
                      <span className="text-zinc-500">π (Pi)</span>
                      <p className="font-mono text-purple-400">[CLASSIFIED]</p>
                    </div>
                    <div>
                      <span className="text-zinc-500">r (Chaos)</span>
                      <p className="font-mono text-red-400">4.0</p>
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-zinc-900/50 p-3 rounded border border-zinc-800">
                    <div className="flex items-center gap-2 mb-2">
                      <Waves className="w-4 h-4 text-purple-400" />
                      <span className="text-xs uppercase text-zinc-500">Poetic Mode</span>
                    </div>
                    <p className="text-xs text-zinc-400">Conjugate inversion for entropy cancellation. Uses backward chaos flood to achieve net-zero entropy delta.</p>
                  </div>
                  <div className="bg-zinc-900/50 p-3 rounded border border-zinc-800">
                    <div className="flex items-center gap-2 mb-2">
                      <Flame className="w-4 h-4 text-red-400" />
                      <span className="text-xs uppercase text-zinc-500">Brute Mode</span>
                    </div>
                    <p className="text-xs text-zinc-400">Triple chaos assault with r=4.0 logistic map. Overwhelms threat entropy through flooding.</p>
                  </div>
                </div>
              </div>

              {/* Entropy Stats */}
              <div className="card-tactical p-4" data-testid="entropy-stats">
                <div className="flex items-center gap-2 mb-4">
                  <TrendingUp className="w-4 h-4 text-emerald-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider">Entropy Stats</h2>
                </div>
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-zinc-500">Avg Threat Entropy</span>
                    <span className="font-mono text-cyan-400">{entropyStats?.average_threat_entropy?.toFixed(4) || '0.0000'}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-zinc-500">Floods Generated</span>
                    <span className="font-mono text-purple-400">{entropyStats?.flood_history_count || 0}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-zinc-500">Poetic Attempts</span>
                    <span className="font-mono text-amber-400">{entropyStats?.neutralization_stats?.poetic_attempts || 0}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-zinc-500">Brute Attempts</span>
                    <span className="font-mono text-red-400">{entropyStats?.neutralization_stats?.brute_attempts || 0}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-zinc-500">Success Rate</span>
                    <span className={`font-mono ${(entropyStats?.neutralization_stats?.success_rate || 0) > 0.7 ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {((entropyStats?.neutralization_stats?.success_rate || 0) * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-zinc-500">Avg Entropy Delta</span>
                    <span className="font-mono text-cyan-400">{entropyStats?.neutralization_stats?.avg_entropy_delta?.toFixed(4) || '0.0000'}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Entropy Actions */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="card-tactical p-4" data-testid="entropy-actions">
                <div className="flex items-center gap-2 mb-4">
                  <Zap className="w-4 h-4 text-amber-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider">Entropy Actions</h2>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <Button
                    onClick={runEntropyScan}
                    disabled={isScanning}
                    data-testid="entropy-scan-btn"
                    className="bg-cyan-600 hover:bg-cyan-700 text-white font-mono text-xs uppercase"
                  >
                    <Atom className="w-4 h-4 mr-2" />
                    Entropy Scan
                  </Button>
                  <Button
                    onClick={runPoeticFlood}
                    disabled={isScanning || activeThreats.length === 0}
                    data-testid="poetic-flood-btn"
                    className="bg-purple-600 hover:bg-purple-700 text-white font-mono text-xs uppercase"
                  >
                    <Waves className="w-4 h-4 mr-2" />
                    Poetic Flood
                  </Button>
                  <Button
                    onClick={runBruteFlood}
                    disabled={isScanning || activeThreats.length === 0}
                    data-testid="brute-flood-btn"
                    className="bg-red-600 hover:bg-red-700 text-white font-mono text-xs uppercase"
                  >
                    <Flame className="w-4 h-4 mr-2" />
                    Brute Flood
                  </Button>
                  <Button
                    onClick={fetchEntropyStats}
                    data-testid="refresh-entropy-btn"
                    variant="outline"
                    className="font-mono text-xs uppercase border-zinc-700"
                  >
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh
                  </Button>
                </div>
              </div>

              {/* Entropy Scan Results */}
              <div className="card-tactical p-4" data-testid="entropy-scan-results">
                <div className="flex items-center gap-2 mb-4">
                  <Target className="w-4 h-4 text-cyan-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider">Scan Results</h2>
                </div>
                <ScrollArea className="h-48">
                  {entropyScanResults?.threat_entropies?.length > 0 ? (
                    <div className="space-y-2">
                      {entropyScanResults.threat_entropies.map((threat, idx) => (
                        <div key={idx} className="p-2 bg-zinc-900/50 rounded border border-zinc-800">
                          <div className="flex justify-between items-center mb-1">
                            <span className="text-xs font-mono text-zinc-300">{threat.threat_name}</span>
                            <Badge className={threat.entropy_score > 0.7 ? 'badge-danger' : threat.entropy_score > 0.5 ? 'badge-warning' : 'badge-safe'}>
                              {(threat.entropy_score * 100).toFixed(1)}%
                            </Badge>
                          </div>
                          <div className="w-full bg-zinc-800 h-1 rounded">
                            <div 
                              className={`h-1 rounded ${threat.entropy_score > 0.7 ? 'bg-red-500' : threat.entropy_score > 0.5 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                              style={{ width: `${threat.entropy_score * 100}%` }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-8 text-zinc-500">
                      <Atom className="w-8 h-8 mb-2 text-zinc-700" />
                      <p className="font-mono text-sm">Run entropy scan to analyze</p>
                    </div>
                  )}
                </ScrollArea>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/10 mt-8 py-4">
        <div className="container mx-auto px-4 flex items-center justify-between text-xs text-zinc-500 font-mono">
          <span>RAT COUNTERMEASURE AGENT // AUTONOMOUS DEFENSE // ENTROPY ENGINE</span>
          <span>Last update: {new Date().toLocaleTimeString()}</span>
        </div>
      </footer>
    </div>
  );
}

export default App;
