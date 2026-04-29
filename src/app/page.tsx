'use client';

import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Switch } from '@/components/ui/switch';
import { Slider } from '@/components/ui/slider';
import { 
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow 
} from '@/components/ui/table';
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
  AlertDialogTrigger
} from '@/components/ui/alert-dialog';
import {
  Shield, Search, Globe, Server, Lock, AlertTriangle, 
  Play, Pause, Download, Trash2, History, Bug, Network,
  Mail, FileText, Activity, ChevronRight, Clock, Target,
  CheckCircle2, XCircle, AlertCircle, Info, Brain, Sparkles,
  Lightbulb, Zap, BarChart3, ShieldAlert
} from 'lucide-react';
import { toast } from 'sonner';
import AIAnalytics from '@/components/ai-analytics';

// Loading Icon component
const LoadingIcon = ({ className }: { className?: string }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
  </svg>
);

// Types
interface Scan {
  id: string;
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'paused';
  progress: number;
  currentPhase: string | null;
  scope: string;
  rateLimit: number;
  createdAt: string;
  completedAt: string | null;
}

interface ScanStats {
  subdomainsFound: number;
  liveIPs: number;
  emailsFound: number;
  openPorts: number;
  vulnsFound: number;
  criticalVulns: number;
}

interface ReconResult {
  whoisData: WhoisData | null;
  dnsRecords: DNSRecord[];
  subdomains: Subdomain[];
  emails: string[];
  liveIPs: string[];
}

interface WhoisData {
  domain: string;
  registrar: string;
  creationDate: string;
  expirationDate: string;
  nameServers: string[];
  registrantCountry: string;
}

interface DNSRecord {
  type: string;
  name: string;
  value: string;
}

interface Subdomain {
  name: string;
  ip: string | null;
  status: string;
}

interface ServiceResult {
  ip: string;
  port: number;
  service: string;
  version: string | null;
  banner: string | null;
  os: string | null;
  cveFlags: string[];
}

interface SSLResult {
  host: string;
  port: number;
  issuer: string;
  subject: string;
  protocol: string;
  cipherSuite: string;
  riskRating: string;
  isExpired: boolean;
  isSelfSigned: boolean;
  daysRemaining: number;
}

interface VulnerabilityResult {
  id: string;
  cveId: string;
  title: string;
  description: string;
  host: string;
  port: number | null;
  service: string | null;
  cvssScore: number;
  severity: string;
  exploitAvailable: boolean;
  status: string;
}

interface AttackSurfaceNode {
  id: string;
  type: string;
  label: string;
  data: Record<string, unknown>;
}

interface AttackSurfaceEdge {
  source: string;
  target: string;
  label?: string;
}

// Phase definitions
const PHASES = [
  { name: 'reconnaissance', label: 'Reconnaissance', icon: Globe },
  { name: 'fingerprinting', label: 'Fingerprinting', icon: Server },
  { name: 'ssl_analysis', label: 'SSL/TLS Analysis', icon: Lock },
  { name: 'vuln_scanning', label: 'Vuln Scanning', icon: Bug },
  { name: 'exploitation', label: 'Exploitation', icon: AlertTriangle },
  { name: 'post_exploitation', label: 'Post-Exploitation', icon: Network },
  { name: 'reporting', label: 'Reporting', icon: FileText },
];

// Severity colors
const severityColors: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
};

// Risk rating colors
const riskColors: Record<string, string> = {
  green: 'bg-green-500',
  yellow: 'bg-yellow-500',
  red: 'bg-red-500',
};

export default function PentestDashboard() {
  // State
  const [target, setTarget] = useState('');
  const [scope, setScope] = useState('full');
  const [rateLimit, setRateLimit] = useState(10);
  const [modules, setModules] = useState({
    whoisEnabled: true,
    dnsEnabled: true,
    subdomainEnabled: true,
    osintEnabled: true,
    shodanEnabled: false,
    asnEnabled: true,
    sslEnabled: true,
    vulnEnabled: true,
  });
  
  const [currentScan, setCurrentScan] = useState<Scan | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [stats, setStats] = useState<ScanStats>({
    subdomainsFound: 0,
    liveIPs: 0,
    emailsFound: 0,
    openPorts: 0,
    vulnsFound: 0,
    criticalVulns: 0,
  });
  
  const [recon, setRecon] = useState<ReconResult | null>(null);
  const [services, setServices] = useState<ServiceResult[]>([]);
  const [sslResults, setSSLResults] = useState<SSLResult[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityResult[]>([]);
  const [attackSurface, setAttackSurface] = useState<{ nodes: AttackSurfaceNode[]; edges: AttackSurfaceEdge[] }>({ nodes: [], edges: [] });
  
  const [isLoading, setIsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  
  // Fetch scans
  const fetchScans = useCallback(async () => {
    try {
      const response = await fetch('/api/scans');
      const data = await response.json();
      if (data.success) {
        setScans(data.data);
      }
    } catch (error) {
      console.error('Error fetching scans:', error);
    }
  }, []);
  
  // Fetch scan results
  const fetchResults = useCallback(async (scanId: string) => {
    try {
      const response = await fetch(`/api/scans/${scanId}/results`);
      const data = await response.json();
      if (data.success) {
        setStats(data.data.stats);
        setRecon(data.data.recon);
        setServices(data.data.services);
        setSSLResults(data.data.ssl);
        setVulnerabilities(data.data.vulnerabilities);
        setAttackSurface(data.data.attackSurface);
      }
    } catch (error) {
      console.error('Error fetching results:', error);
    }
  }, []);
  
  // Poll for scan updates
  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, [fetchScans]);
  
  // Update current scan from scans list
  useEffect(() => {
    if (currentScan) {
      const updated = scans.find(s => s.id === currentScan.id);
      if (updated) {
        setCurrentScan(updated);
        if (updated.status === 'completed' || updated.status === 'failed') {
          fetchResults(updated.id);
        }
      }
    }
  }, [scans, currentScan, fetchResults]);
  
  // Fetch results when scan completes
  useEffect(() => {
    if (selectedScanId) {
      fetchResults(selectedScanId);
    }
  }, [selectedScanId, fetchResults]);
  
  // Start new scan
  const startScan = async () => {
    if (!target) {
      toast.error('Please enter a target domain or IP');
      return;
    }
    
    setIsLoading(true);
    
    try {
      // Create scan
      const createResponse = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scope, rateLimit, modules }),
      });
      
      const createData = await createResponse.json();
      
      if (!createData.success) {
        throw new Error(createData.error);
      }
      
      const scanId = createData.data.scanId;
      
      // Start scan
      const startResponse = await fetch(`/api/scans/${scanId}/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ modules }),
      });
      
      const startData = await startResponse.json();
      
      if (!startData.success) {
        throw new Error(startData.error);
      }
      
      toast.success('Scan started successfully');
      
      // Fetch updated scans
      await fetchScans();
      
      // Set current scan
      const newScan = { id: scanId, target, status: 'running', progress: 0, currentPhase: 'initializing', scope, rateLimit, createdAt: new Date().toISOString(), completedAt: null };
      setCurrentScan(newScan as Scan);
      setSelectedScanId(scanId);
      setActiveTab('results');
      
    } catch (error) {
      toast.error(`Failed to start scan: ${error}`);
    } finally {
      setIsLoading(false);
    }
  };
  
  // Delete scan
  const deleteScan = async (scanId: string) => {
    try {
      const response = await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
      const data = await response.json();
      
      if (data.success) {
        toast.success('Scan deleted');
        fetchScans();
        if (currentScan?.id === scanId) {
          setCurrentScan(null);
        }
      }
    } catch (error) {
      toast.error('Failed to delete scan');
    }
  };
  
  // Export report
  const exportReport = async (scanId: string) => {
    try {
      const response = await fetch(`/api/scans/${scanId}/report?format=json`);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `pentest-report-${scanId}.json`;
      a.click();
      window.URL.revokeObjectURL(url);
      toast.success('Report exported');
    } catch (error) {
      toast.error('Failed to export report');
    }
  };
  
  // Get phase status
  const getPhaseStatus = (phaseName: string): 'pending' | 'running' | 'completed' | 'skipped' => {
    if (!currentScan) return 'pending';
    
    const phaseIndex = PHASES.findIndex(p => p.name === phaseName);
    const currentPhaseIndex = PHASES.findIndex(p => p.name === currentScan.currentPhase);
    
    if (currentScan.status === 'completed') return 'completed';
    if (currentScan.status !== 'running') return 'pending';
    if (phaseName === currentScan.currentPhase) return 'running';
    if (phaseIndex < currentPhaseIndex) return 'completed';
    return 'pending';
  };
  
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b bg-card">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-primary" />
              <div>
                <h1 className="text-2xl font-bold">Pentest Platform</h1>
                <p className="text-sm text-muted-foreground">Automated Penetration Testing</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant={currentScan?.status === 'running' ? 'default' : 'secondary'}>
                {currentScan?.status === 'running' ? (
                  <><Activity className="h-3 w-3 mr-1 animate-pulse" /> Scanning</>
                ) : (
                  <><CheckCircle2 className="h-3 w-3 mr-1" /> Ready</>
                )}
              </Badge>
            </div>
          </div>
        </div>
      </header>
      
      {/* Main Content */}
      <main className="container mx-auto px-4 py-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
            <TabsTrigger value="results">Results</TabsTrigger>
            <TabsTrigger value="analytics">AI Analytics</TabsTrigger>
            <TabsTrigger value="history">History</TabsTrigger>
            <TabsTrigger value="tools">Tools</TabsTrigger>
          </TabsList>
          
          {/* Dashboard Tab */}
          <TabsContent value="dashboard" className="space-y-6">
            <div className="grid gap-6 lg:grid-cols-3">
              {/* Scan Controls */}
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Target className="h-5 w-5" />
                    New Scan
                  </CardTitle>
                  <CardDescription>
                    Configure and start a new penetration test scan
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* Target Input */}
                  <div className="space-y-2">
                    <Label htmlFor="target">Target Domain / IP</Label>
                    <div className="flex gap-2">
                      <Input
                        id="target"
                        placeholder="example.com or 192.168.1.1"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        className="flex-1"
                      />
                      <Button onClick={startScan} disabled={isLoading || !target}>
                        {isLoading ? (
                          <><Activity className="h-4 w-4 mr-2 animate-spin" /> Starting...</>
                        ) : (
                          <><Play className="h-4 w-4 mr-2" /> Start Scan</>
                        )}
                      </Button>
                    </div>
                  </div>
                  
                  {/* Scope Selection */}
                  <div className="space-y-2">
                    <Label>Scan Scope</Label>
                    <div className="flex flex-wrap gap-2">
                      {['full', 'dns', 'osint', 'network'].map((s) => (
                        <Button
                          key={s}
                          variant={scope === s ? 'default' : 'outline'}
                          size="sm"
                          onClick={() => setScope(s)}
                        >
                          {s.toUpperCase()}
                        </Button>
                      ))}
                    </div>
                  </div>
                  
                  {/* Rate Limit */}
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <Label>Rate Limit (req/sec)</Label>
                      <span className="text-sm text-muted-foreground">{rateLimit}</span>
                    </div>
                    <Slider
                      value={[rateLimit]}
                      onValueChange={(v) => setRateLimit(v[0])}
                      min={1}
                      max={50}
                      step={1}
                    />
                    <p className="text-xs text-muted-foreground">
                      Lower values help avoid IDS detection
                    </p>
                  </div>
                  
                  {/* Module Toggles */}
                  <div className="space-y-2">
                    <Label>Modules</Label>
                    <div className="grid grid-cols-2 gap-3">
                      {Object.entries(modules).map(([key, value]) => (
                        <div key={key} className="flex items-center justify-between rounded-lg border p-3">
                          <Label htmlFor={key} className="text-sm capitalize">
                            {key.replace('Enabled', '').replace(/([A-Z])/g, ' $1').trim()}
                          </Label>
                          <Switch
                            id={key}
                            checked={value}
                            onCheckedChange={(checked) => 
                              setModules(prev => ({ ...prev, [key]: checked }))
                            }
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              {/* Current Scan Progress */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Activity className="h-5 w-5" />
                    Current Scan
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {currentScan ? (
                    <>
                      <div className="space-y-2">
                        <div className="flex justify-between text-sm">
                          <span className="font-medium">{currentScan.target}</span>
                          <Badge variant={
                            currentScan.status === 'completed' ? 'default' :
                            currentScan.status === 'running' ? 'secondary' :
                            currentScan.status === 'failed' ? 'destructive' : 'outline'
                          }>
                            {currentScan.status}
                          </Badge>
                        </div>
                        <Progress value={currentScan.progress} />
                        <p className="text-xs text-muted-foreground">
                          {currentScan.currentPhase || 'Initializing...'}
                        </p>
                      </div>
                      
                      {/* Phase Pills */}
                      <div className="space-y-2">
                        {PHASES.map((phase) => {
                          const status = getPhaseStatus(phase.name);
                          const Icon = phase.icon;
                          return (
                            <div
                              key={phase.name}
                              className={`flex items-center gap-2 rounded-md p-2 text-sm ${
                                status === 'running' ? 'bg-primary/10 text-primary' :
                                status === 'completed' ? 'bg-green-500/10 text-green-600' :
                                'bg-muted text-muted-foreground'
                              }`}
                            >
                              <Icon className="h-4 w-4" />
                              <span>{phase.label}</span>
                              {status === 'running' && (
                                <Activity className="h-3 w-3 ml-auto animate-pulse" />
                              )}
                              {status === 'completed' && (
                                <CheckCircle2 className="h-3 w-3 ml-auto" />
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </>
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <Target className="h-12 w-12 mx-auto mb-2 opacity-50" />
                      <p>No active scan</p>
                      <p className="text-xs">Start a new scan to see progress</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
            
            {/* Stats Cards */}
            <div className="grid gap-4 md:grid-cols-6">
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2">
                    <Globe className="h-4 w-4 text-muted-foreground" />
                    <div>
                      <p className="text-2xl font-bold">{stats.subdomainsFound}</p>
                      <p className="text-xs text-muted-foreground">Subdomains</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2">
                    <Server className="h-4 w-4 text-muted-foreground" />
                    <div>
                      <p className="text-2xl font-bold">{stats.liveIPs}</p>
                      <p className="text-xs text-muted-foreground">Live IPs</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2">
                    <Mail className="h-4 w-4 text-muted-foreground" />
                    <div>
                      <p className="text-2xl font-bold">{stats.emailsFound}</p>
                      <p className="text-xs text-muted-foreground">Emails</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2">
                    <Network className="h-4 w-4 text-muted-foreground" />
                    <div>
                      <p className="text-2xl font-bold">{stats.openPorts}</p>
                      <p className="text-xs text-muted-foreground">Open Ports</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2">
                    <Bug className="h-4 w-4 text-muted-foreground" />
                    <div>
                      <p className="text-2xl font-bold">{stats.vulnsFound}</p>
                      <p className="text-xs text-muted-foreground">Vulnerabilities</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500" />
                    <div>
                      <p className="text-2xl font-bold text-red-500">{stats.criticalVulns}</p>
                      <p className="text-xs text-muted-foreground">Critical</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
          
          {/* Results Tab */}
          <TabsContent value="results" className="space-y-6">
            {selectedScanId ? (
              <>
                {/* Recon Results */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Globe className="h-5 w-5" />
                      Reconnaissance Results
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Tabs defaultValue="subdomains">
                      <TabsList>
                        <TabsTrigger value="subdomains">Subdomains</TabsTrigger>
                        <TabsTrigger value="dns">DNS Records</TabsTrigger>
                        <TabsTrigger value="whois">WHOIS</TabsTrigger>
                        <TabsTrigger value="emails">Emails</TabsTrigger>
                      </TabsList>
                      
                      <TabsContent value="subdomains" className="mt-4">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Subdomain</TableHead>
                              <TableHead>IP Address</TableHead>
                              <TableHead>Status</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {recon?.subdomains?.map((sub, i) => (
                              <TableRow key={i}>
                                <TableCell className="font-medium">{sub.name}</TableCell>
                                <TableCell>{sub.ip || '-'}</TableCell>
                                <TableCell>
                                  <Badge variant={sub.status === 'live' ? 'default' : 'secondary'}>
                                    {sub.status}
                                  </Badge>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TabsContent>
                      
                      <TabsContent value="dns" className="mt-4">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Type</TableHead>
                              <TableHead>Name</TableHead>
                              <TableHead>Value</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {recon?.dnsRecords?.map((record, i) => (
                              <TableRow key={i}>
                                <TableCell>
                                  <Badge variant="outline">{record.type}</Badge>
                                </TableCell>
                                <TableCell>{record.name}</TableCell>
                                <TableCell className="font-mono text-sm">{record.value}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TabsContent>
                      
                      <TabsContent value="whois" className="mt-4">
                        {recon?.whoisData ? (
                          <div className="grid gap-4 md:grid-cols-2">
                            <div className="space-y-3">
                              <div>
                                <Label className="text-muted-foreground">Domain</Label>
                                <p className="font-medium">{recon.whoisData.domain}</p>
                              </div>
                              <div>
                                <Label className="text-muted-foreground">Registrar</Label>
                                <p className="font-medium">{recon.whoisData.registrar}</p>
                              </div>
                              <div>
                                <Label className="text-muted-foreground">Country</Label>
                                <p className="font-medium">{recon.whoisData.registrantCountry}</p>
                              </div>
                            </div>
                            <div className="space-y-3">
                              <div>
                                <Label className="text-muted-foreground">Created</Label>
                                <p className="font-medium">{recon.whoisData.creationDate}</p>
                              </div>
                              <div>
                                <Label className="text-muted-foreground">Expires</Label>
                                <p className="font-medium">{recon.whoisData.expirationDate}</p>
                              </div>
                              <div>
                                <Label className="text-muted-foreground">Name Servers</Label>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {recon.whoisData.nameServers.map((ns, i) => (
                                    <Badge key={i} variant="secondary">{ns}</Badge>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </div>
                        ) : (
                          <p className="text-muted-foreground">No WHOIS data available</p>
                        )}
                      </TabsContent>
                      
                      <TabsContent value="emails" className="mt-4">
                        <div className="flex flex-wrap gap-2">
                          {recon?.emails?.map((email, i) => (
                            <Badge key={i} variant="secondary">{email}</Badge>
                          ))}
                        </div>
                      </TabsContent>
                    </Tabs>
                  </CardContent>
                </Card>
                
                {/* Services */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Server className="h-5 w-5" />
                      Service Fingerprinting
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>IP</TableHead>
                          <TableHead>Port</TableHead>
                          <TableHead>Service</TableHead>
                          <TableHead>Version</TableHead>
                          <TableHead>OS</TableHead>
                          <TableHead>CVEs</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {services.map((svc, i) => (
                          <TableRow key={i}>
                            <TableCell className="font-mono">{svc.ip}</TableCell>
                            <TableCell>{svc.port}</TableCell>
                            <TableCell className="capitalize">{svc.service}</TableCell>
                            <TableCell>{svc.version || '-'}</TableCell>
                            <TableCell>{svc.os || '-'}</TableCell>
                            <TableCell>
                              {svc.cveFlags.length > 0 && (
                                <div className="flex flex-wrap gap-1">
                                  {svc.cveFlags.map((cve, j) => (
                                    <Badge key={j} variant="destructive" className="text-xs">
                                      {cve}
                                    </Badge>
                                  ))}
                                </div>
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
                
                {/* SSL Results */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Lock className="h-5 w-5" />
                      SSL/TLS Analysis
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Host</TableHead>
                          <TableHead>Protocol</TableHead>
                          <TableHead>Issuer</TableHead>
                          <TableHead>Days Left</TableHead>
                          <TableHead>Issues</TableHead>
                          <TableHead>Risk</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {sslResults.map((ssl, i) => (
                          <TableRow key={i}>
                            <TableCell className="font-mono">{ssl.host}</TableCell>
                            <TableCell>{ssl.protocol}</TableCell>
                            <TableCell className="max-w-[200px] truncate">{ssl.issuer}</TableCell>
                            <TableCell>
                              <span className={ssl.daysRemaining < 30 ? 'text-red-500' : ''}>
                                {ssl.daysRemaining}
                              </span>
                            </TableCell>
                            <TableCell>
                              <div className="flex flex-wrap gap-1">
                                {ssl.isExpired && <Badge variant="destructive">Expired</Badge>}
                                {ssl.isSelfSigned && <Badge variant="destructive">Self-Signed</Badge>}
                                {ssl.weakProtocol && <Badge variant="secondary">Weak Protocol</Badge>}
                                {ssl.weakCipher && <Badge variant="secondary">Weak Cipher</Badge>}
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className={`w-3 h-3 rounded-full ${riskColors[ssl.riskRating]}`} />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
                
                {/* Vulnerabilities */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Bug className="h-5 w-5" />
                      Vulnerability Priority Queue
                    </CardTitle>
                    <CardDescription>
                      Sorted by CVSS score (highest risk first)
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>CVE ID</TableHead>
                          <TableHead>Title</TableHead>
                          <TableHead>Host</TableHead>
                          <TableHead>Port</TableHead>
                          <TableHead>CVSS</TableHead>
                          <TableHead>Severity</TableHead>
                          <TableHead>Exploit</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {vulnerabilities.map((vuln) => (
                          <TableRow key={vuln.id}>
                            <TableCell className="font-mono">{vuln.cveId}</TableCell>
                            <TableCell className="max-w-[300px] truncate">{vuln.title}</TableCell>
                            <TableCell className="font-mono">{vuln.host}</TableCell>
                            <TableCell>{vuln.port || '-'}</TableCell>
                            <TableCell className="font-bold">{vuln.cvssScore.toFixed(1)}</TableCell>
                            <TableCell>
                              <Badge className={severityColors[vuln.severity]}>
                                {vuln.severity}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              {vuln.exploitAvailable ? (
                                <AlertTriangle className="h-4 w-4 text-red-500" />
                              ) : (
                                <CheckCircle2 className="h-4 w-4 text-green-500" />
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
                
                {/* Attack Surface Graph */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Network className="h-5 w-5" />
                      Attack Surface Graph
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[400px]">
                      <div className="p-4 bg-muted rounded-lg">
                        <div className="grid gap-2">
                          {attackSurface.nodes.slice(0, 20).map((node) => (
                            <div
                              key={node.id}
                              className={`flex items-center gap-2 p-2 rounded border ${
                                node.type === 'vuln' ? 'bg-red-500/10 border-red-500/30' :
                                node.type === 'service' ? 'bg-blue-500/10 border-blue-500/30' :
                                node.type === 'ip' ? 'bg-green-500/10 border-green-500/30' :
                                'bg-muted border-border'
                              }`}
                            >
                              {node.type === 'domain' && <Globe className="h-4 w-4" />}
                              {node.type === 'ip' && <Server className="h-4 w-4" />}
                              {node.type === 'service' && <Network className="h-4 w-4" />}
                              {node.type === 'vuln' && <AlertTriangle className="h-4 w-4 text-red-500" />}
                              <span className="font-mono text-sm">{node.label}</span>
                              <Badge variant="outline" className="ml-auto text-xs">
                                {node.type}
                              </Badge>
                            </div>
                          ))}
                        </div>
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </>
            ) : (
              <Card>
                <CardContent className="py-12">
                  <div className="text-center text-muted-foreground">
                    <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No scan selected</p>
                    <p className="text-sm">Start a new scan or select from history</p>
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>
          
          {/* History Tab */}
          <TabsContent value="history" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <History className="h-5 w-5" />
                  Scan History
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Target</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Progress</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scans.map((scan) => (
                      <TableRow key={scan.id}>
                        <TableCell className="font-medium">{scan.target}</TableCell>
                        <TableCell>
                          <Badge variant={
                            scan.status === 'completed' ? 'default' :
                            scan.status === 'running' ? 'secondary' :
                            scan.status === 'failed' ? 'destructive' : 'outline'
                          }>
                            {scan.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Progress value={scan.progress} className="w-20" />
                            <span className="text-xs">{scan.progress}%</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1 text-muted-foreground">
                            <Clock className="h-3 w-3" />
                            {new Date(scan.createdAt).toLocaleString()}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => {
                                setSelectedScanId(scan.id);
                                setActiveTab('results');
                              }}
                            >
                              <ChevronRight className="h-4 w-4" />
                            </Button>
                            {scan.status === 'completed' && (
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => exportReport(scan.id)}
                              >
                                <Download className="h-4 w-4" />
                              </Button>
                            )}
                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button size="sm" variant="ghost">
                                  <Trash2 className="h-4 w-4 text-red-500" />
                                </Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent>
                                <AlertDialogHeader>
                                  <AlertDialogTitle>Delete Scan</AlertDialogTitle>
                                  <AlertDialogDescription>
                                    Are you sure you want to delete this scan and all its results?
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                                  <AlertDialogAction onClick={() => deleteScan(scan.id)}>
                                    Delete
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                    {scans.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                          No scans found. Start a new scan to see history.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>
          
          {/* Tools Tab */}
          <TabsContent value="tools" className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2">
              {/* CVE Lookup */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Info className="h-5 w-5" />
                    CVE Lookup
                  </CardTitle>
                  <CardDescription>
                    Search for CVE details in local cache
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex gap-2">
                    <Input placeholder="CVE-2021-44228" />
                    <Button>Search</Button>
                  </div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Total CVEs cached:</span>
                      <span className="font-mono">10</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Last updated:</span>
                      <span>{new Date().toLocaleDateString()}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              {/* Hash Cracker */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Lock className="h-5 w-5" />
                    Hash Cracker
                  </CardTitle>
                  <CardDescription>
                    Dictionary attack on discovered hashes
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label>Hash Type</Label>
                    <div className="flex flex-wrap gap-2">
                      {['MD5', 'SHA1', 'SHA256'].map((type) => (
                        <Button key={type} variant="outline" size="sm">
                          {type}
                        </Button>
                      ))}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Input placeholder="Enter hash value" />
                    <Button>Crack</Button>
                  </div>
                </CardContent>
              </Card>
              
              {/* Packet Capture */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Activity className="h-5 w-5" />
                    Packet Capture
                  </CardTitle>
                  <CardDescription>
                    Live packet inspection (requires permissions)
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-center py-8 text-muted-foreground">
                    <div className="text-center">
                      <AlertCircle className="h-8 w-8 mx-auto mb-2" />
                      <p className="text-sm">Feature requires elevated permissions</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              {/* Diff View */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <FileText className="h-5 w-5" />
                    Scan Diff
                  </CardTitle>
                  <CardDescription>
                    Compare two scans side-by-side
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-2">
                    <select className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm">
                      <option>Select Scan 1</option>
                      {scans.map(scan => (
                        <option key={scan.id} value={scan.id}>{scan.target}</option>
                      ))}
                    </select>
                    <select className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm">
                      <option>Select Scan 2</option>
                      {scans.map(scan => (
                        <option key={scan.id} value={scan.id}>{scan.target}</option>
                      ))}
                    </select>
                  </div>
                  <Button className="w-full">Compare Scans</Button>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
          
          {/* AI Analytics Tab */}
          <TabsContent value="analytics" className="space-y-6">
            <AIAnalytics 
              scanId={selectedScanId} 
              vulnerabilities={vulnerabilities}
              sslResults={sslResults}
              services={services}
            />
          </TabsContent>
        </Tabs>
      </main>
      
      {/* Footer */}
      <footer className="border-t bg-card mt-auto">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <p>Automated Penetration Testing Platform - Cybersecurity Lab Project</p>
            <div className="flex items-center gap-4">
              <Badge variant="outline" className="text-xs">
                Authorized Targets Only
              </Badge>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
