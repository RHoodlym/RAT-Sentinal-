import { useState, useEffect, useCallback } from "react";
import "@/App.css";
import axios from "axios";
import { Toaster, toast } from "sonner";
import { 
  ShieldAlert, 
  Activity, 
  Network, 
  Terminal, 
  History, 
  Settings,
  Scan,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  Cpu,
  HardDrive,
  Wifi,
  Eye,
  Zap
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
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
  Cell
} from "recharts";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Stat Card Component
const StatCard = ({ title, value, icon: Icon, status, subtitle }) => {
  const statusColors = {
    safe: "text-emerald-500",
    warning: "text-amber-500",
    danger: "text-red-500",
    neutral: "text-zinc-400"
  };

  return (
    <div className="stat-card" data-testid={`stat-card-${title.toLowerCase().replace(/\s+/g, '-')}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs uppercase tracking-wider text-zinc-500 font-mono">{title}</p>
          <p className={`text-3xl font-bold mt-1 ${statusColors[status] || 'text-white'}`}>
            {value}
          </p>
          {subtitle && <p className="text-xs text-zinc-500 mt-1">{subtitle}</p>}
        </div>
        <div className={`p-2 rounded ${status === 'danger' ? 'bg-red-500/20' : status === 'warning' ? 'bg-amber-500/20' : 'bg-zinc-800'}`}>
          <Icon className={`w-5 h-5 ${statusColors[status] || 'text-zinc-400'}`} />
        </div>
      </div>
    </div>
  );
};

// Detection Row Component
const DetectionRow = ({ detection, onAnalyze, onUpdateStatus, isAnalyzing }) => {
  const severityColors = {
    critical: "badge-danger",
    high: "bg-orange-500/20 text-orange-500 border border-orange-500/50",
    medium: "badge-warning",
    low: "badge-safe"
  };

  const statusColors = {
    active: "badge-danger",
    resolved: "badge-safe",
    false_positive: "badge-neutral"
  };

  return (
    <tr data-testid={`detection-row-${detection.id}`}>
      <td className="font-mono text-xs">{detection.threat_name}</td>
      <td>
        <span className={`inline-block px-2 py-0.5 text-xs rounded ${severityColors[detection.severity]}`}>
          {detection.severity}
        </span>
      </td>
      <td className="text-zinc-400">{detection.detection_type.replace('_', ' ')}</td>
      <td>
        <span className={`inline-block px-2 py-0.5 text-xs rounded ${statusColors[detection.status]}`}>
          {detection.status}
        </span>
      </td>
      <td className="text-right">
        <div className="flex gap-2 justify-end">
          <Button 
            variant="ghost" 
            size="sm"
            onClick={() => onAnalyze(detection.id)}
            disabled={isAnalyzing}
            data-testid={`analyze-btn-${detection.id}`}
            className="text-xs hover:bg-emerald-500/20 hover:text-emerald-500"
          >
            <Eye className="w-3 h-3 mr-1" />
            AI Analyze
          </Button>
          {detection.status === 'active' && (
            <Button 
              variant="ghost" 
              size="sm"
              onClick={() => onUpdateStatus(detection.id, 'resolved')}
              data-testid={`resolve-btn-${detection.id}`}
              className="text-xs hover:bg-emerald-500/20 hover:text-emerald-500"
            >
              <CheckCircle className="w-3 h-3 mr-1" />
              Resolve
            </Button>
          )}
        </div>
      </td>
    </tr>
  );
};

// Log Entry Component
const LogEntry = ({ timestamp, level, message }) => {
  const levelColors = {
    info: "log-info",
    safe: "log-safe",
    warning: "log-warning",
    danger: "log-danger"
  };

  return (
    <div className="log-entry mb-1" data-testid="log-entry">
      <span className="timestamp">[{timestamp}]</span>
      <span className={levelColors[level]}>{message}</span>
    </div>
  );
};

// Main Dashboard
function App() {
  const [systemStatus, setSystemStatus] = useState(null);
  const [detections, setDetections] = useState([]);
  const [connections, setConnections] = useState([]);
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanningFile, setScanningFile] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [networkData, setNetworkData] = useState([]);

  // Generate fake file names for scanning animation
  const fakeFiles = [
    "C:\\Windows\\System32\\ntdll.dll",
    "C:\\Users\\User\\AppData\\Local\\Temp\\cache.dat",
    "C:\\Program Files\\Common Files\\services.exe",
    "C:\\Windows\\SysWOW64\\kernel32.dll",
    "C:\\Users\\User\\Downloads\\setup.exe",
    "C:\\Windows\\System32\\drivers\\http.sys",
    "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys",
    "C:\\Users\\User\\AppData\\Roaming\\config.ini"
  ];

  // Add log entry
  const addLog = useCallback((level, message) => {
    const now = new Date();
    const timestamp = now.toLocaleTimeString('en-US', { hour12: false });
    setLogs(prev => [{timestamp, level, message}, ...prev].slice(0, 100));
  }, []);

  // Fetch system status
  const fetchStatus = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/status`);
      setSystemStatus(response.data);
    } catch (e) {
      console.error("Failed to fetch status:", e);
    }
  }, []);

  // Fetch detections
  const fetchDetections = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/detections`);
      setDetections(response.data);
    } catch (e) {
      console.error("Failed to fetch detections:", e);
    }
  }, []);

  // Fetch network connections
  const fetchConnections = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/network/connections`);
      setConnections(response.data);
      
      // Generate network data for chart
      const suspicious = response.data.filter(c => c.is_suspicious).length;
      const safe = response.data.length - suspicious;
      
      setNetworkData(prev => {
        const newData = [...prev, {
          time: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
          connections: response.data.length,
          suspicious: suspicious
        }].slice(-20);
        return newData;
      });
    } catch (e) {
      console.error("Failed to fetch connections:", e);
    }
  }, []);

  // Fetch statistics
  const fetchStats = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/stats`);
      setStats(response.data);
    } catch (e) {
      console.error("Failed to fetch stats:", e);
    }
  }, []);

  // Start scan
  const startScan = async (scanType = 'full') => {
    setIsScanning(true);
    setScanProgress(0);
    addLog('info', `Starting ${scanType} system scan...`);
    toast.info('Scan initiated', { description: 'Scanning system for threats...' });

    // Simulate scanning progress
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 95) {
          clearInterval(progressInterval);
          return prev;
        }
        return prev + Math.random() * 10;
      });
      setScanningFile(fakeFiles[Math.floor(Math.random() * fakeFiles.length)]);
    }, 200);

    try {
      const response = await axios.post(`${API}/scan`, { scan_type: scanType });
      clearInterval(progressInterval);
      setScanProgress(100);
      
      if (response.data.threats_found > 0) {
        addLog('danger', `ALERT: ${response.data.threats_found} threat(s) detected!`);
        toast.error('Threats Detected!', { 
          description: `Found ${response.data.threats_found} potential threat(s)` 
        });
      } else {
        addLog('safe', 'Scan complete. No threats detected.');
        toast.success('Scan Complete', { description: 'No threats detected' });
      }

      addLog('info', `Scanned ${response.data.items_scanned} items in ${response.data.duration.toFixed(2)}s`);
      
      // Refresh data
      await Promise.all([fetchStatus(), fetchDetections(), fetchStats()]);
    } catch (e) {
      clearInterval(progressInterval);
      addLog('danger', 'Scan failed: ' + e.message);
      toast.error('Scan Failed', { description: e.message });
    } finally {
      setIsScanning(false);
      setScanProgress(0);
      setScanningFile('');
    }
  };

  // AI Analysis
  const analyzeDetection = async (detectionId) => {
    setIsAnalyzing(true);
    addLog('info', `Running AI analysis on detection ${detectionId.slice(0, 8)}...`);
    toast.info('AI Analysis', { description: 'Analyzing threat with AI...' });

    try {
      const response = await axios.post(`${API}/detections/${detectionId}/analyze`);
      addLog('safe', 'AI analysis complete');
      toast.success('Analysis Complete', { 
        description: response.data.ai_analysis.slice(0, 100) + '...' 
      });
      await fetchDetections();
    } catch (e) {
      addLog('danger', 'AI analysis failed: ' + e.message);
      toast.error('Analysis Failed', { description: e.message });
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Update detection status
  const updateDetectionStatus = async (detectionId, status) => {
    try {
      await axios.patch(`${API}/detections/${detectionId}/status?status=${status}`);
      addLog('safe', `Detection ${detectionId.slice(0, 8)} marked as ${status}`);
      toast.success('Status Updated', { description: `Marked as ${status}` });
      await Promise.all([fetchDetections(), fetchStatus(), fetchStats()]);
    } catch (e) {
      toast.error('Update Failed', { description: e.message });
    }
  };

  // Initial load and polling
  useEffect(() => {
    addLog('info', 'RAT Detection System initialized');
    addLog('safe', 'Monitoring active connections...');
    
    fetchStatus();
    fetchDetections();
    fetchConnections();
    fetchStats();

    // Poll for updates
    const statusInterval = setInterval(fetchStatus, 10000);
    const connectionsInterval = setInterval(fetchConnections, 15000);

    return () => {
      clearInterval(statusInterval);
      clearInterval(connectionsInterval);
    };
  }, [addLog, fetchStatus, fetchDetections, fetchConnections, fetchStats]);

  // Pie chart data
  const threatDistribution = stats ? [
    { name: 'Active', value: stats.active_threats, color: '#EF4444' },
    { name: 'Resolved', value: stats.resolved_threats, color: '#10B981' },
    { name: 'False Positive', value: stats.false_positives, color: '#71717A' }
  ].filter(d => d.value > 0) : [];

  const suspiciousConnections = connections.filter(c => c.is_suspicious);

  return (
    <div className="App min-h-screen bg-[#09090B]" data-testid="rat-detection-dashboard">
      <Toaster position="top-right" theme="dark" />
      <div className="noise-overlay" />
      
      {/* Header */}
      <header className="border-b border-white/10 bg-black/40 backdrop-blur-md sticky top-0 z-50">
        <div className="container mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-500/20 rounded">
              <ShieldAlert className="w-6 h-6 text-red-500" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight glitch-hover" data-testid="app-title">
                RAT DETECTION SYSTEM
              </h1>
              <p className="text-xs text-zinc-500 font-mono">v1.0.0 // PASSIVE MONITORING</p>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            {/* System Status Indicator */}
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded ${
              systemStatus?.threat_level === 'danger' ? 'bg-red-500/20 border border-red-500/50' :
              systemStatus?.threat_level === 'warning' ? 'bg-amber-500/20 border border-amber-500/50' :
              'bg-emerald-500/20 border border-emerald-500/50'
            }`} data-testid="system-status-indicator">
              <div className={`w-2 h-2 rounded-full ${
                systemStatus?.threat_level === 'danger' ? 'bg-red-500 threat-glow' :
                systemStatus?.threat_level === 'warning' ? 'bg-amber-500 blink' :
                'bg-emerald-500 safe-glow'
              }`} />
              <span className={`text-xs font-mono uppercase ${
                systemStatus?.threat_level === 'danger' ? 'text-red-500' :
                systemStatus?.threat_level === 'warning' ? 'text-amber-500' :
                'text-emerald-500'
              }`}>
                {systemStatus?.threat_level || 'LOADING'}
              </span>
            </div>

            {/* Scan Button */}
            <Button
              onClick={() => startScan('full')}
              disabled={isScanning}
              data-testid="scan-now-btn"
              className="bg-emerald-600 hover:bg-emerald-700 text-white font-mono text-xs uppercase tracking-wider"
            >
              {isScanning ? (
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Scan className="w-4 h-4 mr-2" />
              )}
              {isScanning ? 'SCANNING...' : 'SCAN NOW'}
            </Button>
          </div>
        </div>

        {/* Scan Progress Bar */}
        {isScanning && (
          <div className="px-4 pb-3">
            <Progress value={scanProgress} className="h-1 bg-zinc-800" />
            <p className="text-xs font-mono text-zinc-500 mt-1 truncate">
              Scanning: {scanningFile}
            </p>
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-6">
        {/* Stats Row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <StatCard
            title="Active Threats"
            value={systemStatus?.active_threats || 0}
            icon={AlertTriangle}
            status={systemStatus?.active_threats > 0 ? 'danger' : 'safe'}
            subtitle="Requires attention"
          />
          <StatCard
            title="Total Detections"
            value={stats?.total_detections || 0}
            icon={ShieldAlert}
            status="neutral"
            subtitle="All time"
          />
          <StatCard
            title="Active Connections"
            value={systemStatus?.active_connections || 0}
            icon={Wifi}
            status={suspiciousConnections.length > 0 ? 'warning' : 'neutral'}
            subtitle={`${suspiciousConnections.length} suspicious`}
          />
          <StatCard
            title="System Health"
            value={`${systemStatus?.cpu_usage || 0}%`}
            icon={Cpu}
            status={systemStatus?.cpu_usage > 80 ? 'warning' : 'safe'}
            subtitle={`Memory: ${systemStatus?.memory_usage || 0}%`}
          />
        </div>

        {/* Main Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Network Monitor */}
          <div className="lg:col-span-2 space-y-6">
            {/* Network Traffic Chart */}
            <div className="card-tactical p-4 scanlines" data-testid="network-chart">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Network className="w-4 h-4 text-emerald-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider">Network Activity</h2>
                </div>
                <Button variant="ghost" size="sm" onClick={fetchConnections} className="text-xs">
                  <RefreshCw className="w-3 h-3 mr-1" /> Refresh
                </Button>
              </div>
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={networkData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#27272A" />
                    <XAxis dataKey="time" stroke="#71717A" fontSize={10} />
                    <YAxis stroke="#71717A" fontSize={10} />
                    <Tooltip 
                      contentStyle={{ 
                        background: '#18181B', 
                        border: '1px solid #27272A',
                        borderRadius: '4px',
                        fontSize: '12px'
                      }} 
                    />
                    <Line 
                      type="monotone" 
                      dataKey="connections" 
                      stroke="#10B981" 
                      strokeWidth={2}
                      dot={false}
                      name="Total"
                    />
                    <Line 
                      type="monotone" 
                      dataKey="suspicious" 
                      stroke="#EF4444" 
                      strokeWidth={2}
                      dot={false}
                      name="Suspicious"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Detections Table */}
            <div className="card-tactical p-4" data-testid="detections-table">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider">Recent Detections</h2>
                </div>
                <Badge variant="outline" className="font-mono text-xs">
                  {detections.length} items
                </Badge>
              </div>
              
              {detections.length > 0 ? (
                <ScrollArea className="h-64">
                  <table className="detection-table">
                    <thead>
                      <tr>
                        <th>Threat</th>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th className="text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detections.map(detection => (
                        <DetectionRow
                          key={detection.id}
                          detection={detection}
                          onAnalyze={analyzeDetection}
                          onUpdateStatus={updateDetectionStatus}
                          isAnalyzing={isAnalyzing}
                        />
                      ))}
                    </tbody>
                  </table>
                </ScrollArea>
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-zinc-500">
                  <CheckCircle className="w-12 h-12 mb-3 text-emerald-500/50" />
                  <p className="font-mono text-sm">No threats detected</p>
                  <p className="text-xs mt-1">System is clean</p>
                </div>
              )}
            </div>

            {/* Suspicious Connections */}
            {suspiciousConnections.length > 0 && (
              <div className="card-tactical p-4 border-red-500/30" data-testid="suspicious-connections">
                <div className="flex items-center gap-2 mb-4">
                  <Zap className="w-4 h-4 text-red-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider text-red-500">
                    Suspicious Connections
                  </h2>
                </div>
                <ScrollArea className="h-32">
                  <div className="space-y-2">
                    {suspiciousConnections.map(conn => (
                      <div 
                        key={conn.id} 
                        className="flex items-center justify-between p-2 bg-red-500/10 rounded border border-red-500/20"
                        data-testid={`suspicious-conn-${conn.id}`}
                      >
                        <div className="font-mono text-xs">
                          <span className="text-zinc-400">{conn.local_address}</span>
                          <span className="text-zinc-600 mx-2">→</span>
                          <span className="text-red-400">{conn.remote_address}:{conn.remote_port}</span>
                        </div>
                        <Badge className="badge-danger text-xs">{conn.process_name}</Badge>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </div>
            )}
          </div>

          {/* Right Column */}
          <div className="space-y-6">
            {/* Threat Distribution */}
            {threatDistribution.length > 0 && (
              <div className="card-tactical p-4" data-testid="threat-distribution">
                <div className="flex items-center gap-2 mb-4">
                  <Activity className="w-4 h-4 text-amber-500" />
                  <h2 className="text-sm font-bold uppercase tracking-wider">Threat Distribution</h2>
                </div>
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={threatDistribution}
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={70}
                        paddingAngle={2}
                        dataKey="value"
                      >
                        {threatDistribution.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ 
                          background: '#18181B', 
                          border: '1px solid #27272A',
                          borderRadius: '4px',
                          fontSize: '12px'
                        }} 
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex justify-center gap-4 mt-2">
                  {threatDistribution.map(item => (
                    <div key={item.name} className="flex items-center gap-2 text-xs">
                      <div className="w-2 h-2 rounded-full" style={{ background: item.color }} />
                      <span className="text-zinc-400">{item.name}: {item.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Quick Actions */}
            <div className="card-tactical p-4" data-testid="quick-actions">
              <div className="flex items-center gap-2 mb-4">
                <Settings className="w-4 h-4 text-zinc-400" />
                <h2 className="text-sm font-bold uppercase tracking-wider">Quick Actions</h2>
              </div>
              <div className="space-y-2">
                <Button 
                  variant="outline" 
                  className="w-full justify-start text-xs font-mono bg-transparent border-zinc-800 hover:bg-zinc-800"
                  onClick={() => startScan('quick')}
                  disabled={isScanning}
                  data-testid="quick-scan-btn"
                >
                  <Scan className="w-4 h-4 mr-2 text-emerald-500" />
                  Quick Scan
                </Button>
                <Button 
                  variant="outline" 
                  className="w-full justify-start text-xs font-mono bg-transparent border-zinc-800 hover:bg-zinc-800"
                  onClick={fetchConnections}
                  data-testid="refresh-connections-btn"
                >
                  <Network className="w-4 h-4 mr-2 text-blue-500" />
                  Refresh Connections
                </Button>
                <Button 
                  variant="outline" 
                  className="w-full justify-start text-xs font-mono bg-transparent border-zinc-800 hover:bg-zinc-800"
                  onClick={() => {
                    fetchStatus();
                    fetchStats();
                    toast.success('Status refreshed');
                  }}
                  data-testid="refresh-status-btn"
                >
                  <RefreshCw className="w-4 h-4 mr-2 text-amber-500" />
                  Refresh Status
                </Button>
              </div>
            </div>

            {/* System Logs */}
            <div className="card-tactical" data-testid="system-logs">
              <div className="flex items-center gap-2 p-4 border-b border-white/10">
                <Terminal className="w-4 h-4 text-emerald-500" />
                <h2 className="text-sm font-bold uppercase tracking-wider">System Log</h2>
              </div>
              <ScrollArea className="h-64">
                <div className="terminal-log">
                  {logs.map((log, idx) => (
                    <LogEntry key={idx} {...log} />
                  ))}
                  {logs.length === 0 && (
                    <div className="text-zinc-500 terminal-cursor">Awaiting input...</div>
                  )}
                </div>
              </ScrollArea>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/10 mt-8 py-4">
        <div className="container mx-auto px-4 flex items-center justify-between text-xs text-zinc-500 font-mono">
          <span>RAT DETECTION SYSTEM // PASSIVE MONITORING</span>
          <span>Last update: {new Date().toLocaleTimeString()}</span>
        </div>
      </footer>
    </div>
  );
}

export default App;
