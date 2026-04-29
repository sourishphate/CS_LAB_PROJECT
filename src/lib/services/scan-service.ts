// Core Scan Service - Handles all phases of penetration testing
import { db } from '@/lib/db';
import type { 
  Scan, 
  ReconResult, 
  ServiceInfo, 
  SSLInfo, 
  Vulnerability,
  ModuleConfig,
  ScanStats,
  Phase
} from '@/types/pentest';

// Phase definitions
export const PHASES: { name: Phase; label: string }[] = [
  { name: 'reconnaissance', label: 'Reconnaissance' },
  { name: 'fingerprinting', label: 'Service Fingerprinting' },
  { name: 'ssl_analysis', label: 'SSL/TLS Analysis' },
  { name: 'vuln_scanning', label: 'Vulnerability Scanning' },
  { name: 'exploitation', label: 'Exploitation Engine' },
  { name: 'post_exploitation', label: 'Post-Exploitation' },
  { name: 'reporting', label: 'Reporting' },
];

// Simulated CVE database for demo
const CVE_DATABASE: Record<string, { title: string; cvss: number; severity: string }> = {
  'CVE-2021-44228': { title: 'Apache Log4j Remote Code Execution', cvss: 10.0, severity: 'critical' },
  'CVE-2021-45046': { title: 'Apache Log4j Denial of Service', cvss: 9.0, severity: 'critical' },
  'CVE-2022-22965': { title: 'Spring4Shell RCE', cvss: 9.8, severity: 'critical' },
  'CVE-2021-34527': { title: 'PrintNightmare RCE', cvss: 8.8, severity: 'high' },
  'CVE-2021-36942': { title: 'Windows LSA Spoofing', cvss: 8.1, severity: 'high' },
  'CVE-2020-1472': { title: 'Zerologon Elevation of Privilege', cvss: 8.8, severity: 'high' },
  'CVE-2019-0708': { title: 'BlueKeep RCE', cvss: 9.3, severity: 'critical' },
  'CVE-2017-0144': { title: 'EternalBlue SMB RCE', cvss: 8.1, severity: 'high' },
  'CVE-2018-8174': { title: 'VBScript Engine RCE', cvss: 7.5, severity: 'high' },
  'CVE-2019-11510': { title: 'Pulse Secure RCE', cvss: 10.0, severity: 'critical' },
};

// Generate simulated data based on target
function generateSimulatedData(target: string) {
  const baseDomain = target.replace(/^(https?:\/\/)?/, '').split('/')[0];
  
  return {
    // Simulated WHOIS data
    whois: {
      domain: baseDomain,
      registrar: 'Example Registrar Inc.',
      creationDate: '2020-01-15',
      expirationDate: '2025-01-15',
      nameServers: ['ns1.example.com', 'ns2.example.com'],
      registrantCountry: 'US',
      status: ['clientTransferProhibited'],
    },
    
    // Simulated DNS records
    dnsRecords: [
      { type: 'A' as const, name: baseDomain, value: '192.168.1.100' },
      { type: 'A' as const, name: `www.${baseDomain}`, value: '192.168.1.100' },
      { type: 'MX' as const, name: baseDomain, value: '10 mail.example.com' },
      { type: 'NS' as const, name: baseDomain, value: 'ns1.example.com' },
      { type: 'NS' as const, name: baseDomain, value: 'ns2.example.com' },
      { type: 'TXT' as const, name: baseDomain, value: 'v=spf1 include:_spf.example.com ~all' },
    ],
    
    // Simulated subdomains
    subdomains: [
      { name: `www.${baseDomain}`, ip: '192.168.1.100', status: 'live' as const },
      { name: `mail.${baseDomain}`, ip: '192.168.1.101', status: 'live' as const },
      { name: `ftp.${baseDomain}`, ip: '192.168.1.102', status: 'live' as const },
      { name: `admin.${baseDomain}`, ip: '192.168.1.103', status: 'live' as const },
      { name: `dev.${baseDomain}`, ip: '192.168.1.104', status: 'live' as const },
      { name: `api.${baseDomain}`, ip: '192.168.1.105', status: 'live' as const },
      { name: `staging.${baseDomain}`, ip: null, status: 'dead' as const },
      { name: `test.${baseDomain}`, ip: null, status: 'dead' as const },
    ],
    
    // Simulated OSINT data
    osint: {
      emails: [
        `admin@${baseDomain}`,
        `support@${baseDomain}`,
        `info@${baseDomain}`,
        `contact@${baseDomain}`,
      ],
      names: ['John Smith', 'Jane Doe', 'Admin User'],
      hosts: [baseDomain, `www.${baseDomain}`, `mail.${baseDomain}`],
      urls: [`https://${baseDomain}`, `https://www.${baseDomain}`],
    },
    
    // Simulated live IPs
    liveIPs: ['192.168.1.100', '192.168.1.101', '192.168.1.102', '192.168.1.103', '192.168.1.104', '192.168.1.105'],
  };
}

// Simulated service fingerprints
function generateServiceFingerprints(ips: string[]): ServiceInfo[] {
  const services: ServiceInfo[] = [];
  const commonPorts = [
    { port: 22, service: 'ssh', version: 'OpenSSH 8.2p1' },
    { port: 80, service: 'http', version: 'Apache/2.4.41' },
    { port: 443, service: 'https', version: 'nginx/1.18.0' },
    { port: 21, service: 'ftp', version: 'vsftpd 3.0.3' },
    { port: 25, service: 'smtp', version: 'Postfix 3.4.13' },
    { port: 3306, service: 'mysql', version: 'MySQL 8.0.25' },
    { port: 3389, service: 'rdp', version: 'Microsoft Terminal Services' },
  ];
  
  ips.forEach((ip, ipIndex) => {
    // Each IP gets 3-5 random services
    const numServices = 3 + Math.floor(Math.random() * 3);
    const shuffled = [...commonPorts].sort(() => Math.random() - 0.5);
    
    shuffled.slice(0, numServices).forEach(({ port, service, version }) => {
      const cveFlags: string[] = [];
      
      // Add some CVEs randomly
      if (Math.random() > 0.6) {
        const cveKeys = Object.keys(CVE_DATABASE);
        const randomCVE = cveKeys[Math.floor(Math.random() * cveKeys.length)];
        cveFlags.push(randomCVE);
      }
      
      services.push({
        ip,
        port,
        protocol: 'tcp',
        service,
        version,
        banner: `${service.toUpperCase()} Server ${version}`,
        os: ipIndex % 2 === 0 ? 'Linux' : 'Windows',
        cveFlags,
      });
    });
  });
  
  return services;
}

// Simulated SSL/TLS results
function generateSSLResults(ips: string[], domain: string): SSLInfo[] {
  return ips.filter(ip => ip.includes('100') || ip.includes('101') || ip.includes('105')).map(ip => {
    const isWeak = Math.random() > 0.7;
    const isExpired = Math.random() > 0.9;
    const isSelfSigned = Math.random() > 0.85;
    
    let riskRating: 'green' | 'yellow' | 'red' = 'green';
    if (isExpired || isSelfSigned || isWeak) {
      riskRating = isExpired || isSelfSigned ? 'red' : 'yellow';
    }
    
    return {
      host: ip,
      port: 443,
      issuer: isSelfSigned ? domain : "Let's Encrypt Authority X3",
      subject: domain,
      validFrom: '2024-01-01',
      validTo: isExpired ? '2024-06-01' : '2025-01-01',
      daysRemaining: isExpired ? -30 : Math.floor(Math.random() * 200) + 30,
      isExpired,
      isSelfSigned,
      cnMismatch: false,
      protocol: isWeak ? 'TLS 1.0' : 'TLS 1.3',
      cipherSuite: isWeak ? 'TLS_RSA_WITH_AES_128_CBC_SHA' : 'TLS_AES_256_GCM_SHA384',
      keySize: isWeak ? 1024 : 2048,
      weakProtocol: isWeak,
      weakCipher: isWeak,
      weakKey: isWeak,
      chainValid: !isSelfSigned,
      riskRating,
    };
  });
}

// Simulated vulnerabilities
function generateVulnerabilities(services: ServiceInfo[]): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  
  services.forEach(service => {
    service.cveFlags.forEach(cveId => {
      const cveData = CVE_DATABASE[cveId];
      if (cveData) {
        vulns.push({
          id: `vuln-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          cveId,
          title: cveData.title,
          description: `Vulnerability ${cveId} detected on ${service.service} service at ${service.ip}:${service.port}`,
          host: service.ip,
          port: service.port,
          service: service.service,
          cvssScore: cveData.cvss,
          severity: cveData.severity as 'critical' | 'high' | 'medium' | 'low',
          exploitAvailable: cveData.cvss >= 9.0,
          status: 'open',
          references: [
            `https://nvd.nist.gov/vuln/detail/${cveId}`,
            `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`,
          ],
        });
      }
    });
  });
  
  // Sort by CVSS score (max-heap behavior)
  return vulns.sort((a, b) => b.cvssScore - a.cvssScore);
}

// Main scan execution
export class ScanService {
  private scanId: string;
  private target: string;
  private config: ModuleConfig;
  private updateCallback?: (phase: Phase, progress: number, stats: Partial<ScanStats>) => void;
  
  constructor(scanId: string, target: string, config: ModuleConfig) {
    this.scanId = scanId;
    this.target = target;
    this.config = config;
  }
  
  onUpdate(callback: (phase: Phase, progress: number, stats: Partial<ScanStats>) => void) {
    this.updateCallback = callback;
  }
  
  private emit(phase: Phase, progress: number, stats: Partial<ScanStats> = {}) {
    this.updateCallback?.(phase, progress, stats);
  }
  
  // Phase 1: Reconnaissance
  async runReconnaissance(): Promise<ReconResult> {
    this.emit('reconnaissance', 0);
    
    const simulated = generateSimulatedData(this.target);
    const result: ReconResult = {
      whois: this.config.whoisEnabled ? simulated.whois : null,
      dnsRecords: this.config.dnsEnabled ? simulated.dnsRecords : [],
      subdomains: this.config.subdomainEnabled ? simulated.subdomains : [],
      osint: this.config.osintEnabled ? simulated.osint : { emails: [], names: [], hosts: [], urls: [] },
      asnData: this.config.asnEnabled ? [{ asn: 'AS12345', organization: 'Example Org', cidr: '192.168.1.0/24', country: 'US' }] : [],
      shodanData: [],
      liveIPs: simulated.liveIPs,
    };
    
    // Simulate progress
    for (let i = 0; i <= 100; i += 10) {
      await this.delay(100);
      this.emit('reconnaissance', i, {
        subdomainsFound: Math.floor(result.subdomains.length * i / 100),
        liveIPs: Math.floor(result.liveIPs.length * i / 100),
        emailsFound: Math.floor(result.osint.emails.length * i / 100),
      });
    }
    
    // Save to database
    await db.reconResult.create({
      data: {
        scanId: this.scanId,
        whoisData: result.whois ? JSON.stringify(result.whois) : null,
        dnsRecords: JSON.stringify(result.dnsRecords),
        subdomains: JSON.stringify(result.subdomains),
        emails: JSON.stringify(result.osint.emails),
        names: JSON.stringify(result.osint.names),
        asnData: result.asnData.length > 0 ? JSON.stringify(result.asnData) : null,
        liveIPs: JSON.stringify(result.liveIPs),
      },
    });
    
    return result;
  }
  
  // Phase 2: Service Fingerprinting
  async runFingerprinting(liveIPs: string[]): Promise<ServiceInfo[]> {
    this.emit('fingerprinting', 0);
    
    const services = generateServiceFingerprints(liveIPs);
    
    for (let i = 0; i <= 100; i += 10) {
      await this.delay(80);
      this.emit('fingerprinting', i, {
        openPorts: Math.floor(services.length * i / 100),
      });
    }
    
    // Save to database
    for (const service of services) {
      await db.serviceResult.create({
        data: {
          scanId: this.scanId,
          ip: service.ip,
          port: service.port,
          protocol: service.protocol,
          service: service.service,
          version: service.version,
          banner: service.banner,
          os: service.os,
          cveFlags: JSON.stringify(service.cveFlags),
        },
      });
    }
    
    return services;
  }
  
  // Phase 3: SSL/TLS Analysis
  async runSSLAnalysis(liveIPs: string[]): Promise<SSLInfo[]> {
    this.emit('ssl_analysis', 0);
    
    const sslResults = generateSSLResults(liveIPs, this.target);
    
    for (let i = 0; i <= 100; i += 20) {
      await this.delay(100);
      this.emit('ssl_analysis', i);
    }
    
    // Save to database
    for (const ssl of sslResults) {
      await db.sSLResult.create({
        data: {
          scanId: this.scanId,
          host: ssl.host,
          port: ssl.port,
          issuer: ssl.issuer,
          subject: ssl.subject,
          validFrom: ssl.validFrom,
          validTo: ssl.validTo,
          daysRemaining: ssl.daysRemaining,
          isExpired: ssl.isExpired,
          isSelfSigned: ssl.isSelfSigned,
          cnMismatch: ssl.cnMismatch,
          protocol: ssl.protocol,
          cipherSuite: ssl.cipherSuite,
          keySize: ssl.keySize,
          weakProtocol: ssl.weakProtocol,
          weakCipher: ssl.weakCipher,
          weakKey: ssl.weakKey,
          chainValid: ssl.chainValid,
          riskRating: ssl.riskRating,
        },
      });
    }
    
    return sslResults;
  }
  
  // Phase 4: Vulnerability Scanning
  async runVulnScanning(services: ServiceInfo[]): Promise<Vulnerability[]> {
    this.emit('vuln_scanning', 0);
    
    const vulns = generateVulnerabilities(services);
    
    for (let i = 0; i <= 100; i += 15) {
      await this.delay(100);
      this.emit('vuln_scanning', i, {
        vulnsFound: Math.floor(vulns.length * i / 100),
        criticalVulns: Math.floor(vulns.filter(v => v.severity === 'critical').length * i / 100),
      });
    }
    
    // Save to database
    for (const vuln of vulns) {
      await db.vulnerabilityResult.create({
        data: {
          scanId: this.scanId,
          cveId: vuln.cveId,
          title: vuln.title,
          description: vuln.description,
          host: vuln.host,
          port: vuln.port,
          service: vuln.service,
          cvssScore: vuln.cvssScore,
          severity: vuln.severity,
          exploitAvailable: vuln.exploitAvailable,
          status: vuln.status,
          references: JSON.stringify(vuln.references),
        },
      });
    }
    
    return vulns;
  }
  
  // Phase 5: Exploitation (simplified/safe mode)
  async runExploitation(vulns: Vulnerability[]): Promise<{ tested: number; successful: number }> {
    this.emit('exploitation', 0);
    
    const exploitable = vulns.filter(v => v.exploitAvailable);
    let successful = 0;
    
    for (let i = 0; i <= 100; i += 25) {
      await this.delay(100);
      this.emit('exploitation', i);
    }
    
    // In safe mode, we only simulate
    successful = Math.floor(exploitable.length * 0.3); // 30% success rate simulation
    
    return { tested: exploitable.length, successful };
  }
  
  // Phase 6: Post-Exploitation (simplified)
  async runPostExploitation(): Promise<{ findings: string[] }> {
    this.emit('post_exploitation', 0);
    
    for (let i = 0; i <= 100; i += 25) {
      await this.delay(80);
      this.emit('post_exploitation', i);
    }
    
    return { findings: ['Privilege escalation possible', 'Credential harvesting potential'] };
  }
  
  // Phase 7: Reporting
  async runReporting(stats: ScanStats): Promise<void> {
    this.emit('reporting', 0);
    
    for (let i = 0; i <= 100; i += 20) {
      await this.delay(50);
      this.emit('reporting', i);
    }
    
    // Calculate risk score
    const riskScore = Math.min(100, 
      stats.criticalVulns * 25 + 
      stats.vulnsFound * 5 + 
      (stats.openPorts > 20 ? 10 : 0)
    );
    
    // Create report
    await db.report.create({
      data: {
        scanId: this.scanId,
        totalHosts: stats.liveIPs,
        totalPorts: stats.openPorts,
        totalVulns: stats.vulnsFound,
        criticalVulns: stats.criticalVulns,
        highVulns: Math.floor(stats.vulnsFound * 0.3),
        mediumVulns: Math.floor(stats.vulnsFound * 0.4),
        lowVulns: Math.floor(stats.vulnsFound * 0.3),
        riskScore,
        complianceData: JSON.stringify({
          nist: { score: Math.max(0, 100 - riskScore) },
          cis: { score: Math.max(0, 100 - riskScore) },
        }),
      },
    });
  }
  
  // Utility: delay function
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  // Run complete scan
  async runFullScan(): Promise<ScanStats> {
    const stats: ScanStats = {
      subdomainsFound: 0,
      liveIPs: 0,
      emailsFound: 0,
      openPorts: 0,
      vulnsFound: 0,
      criticalVulns: 0,
    };
    
    try {
      // Phase 1: Reconnaissance
      const reconResult = await this.runReconnaissance();
      stats.subdomainsFound = reconResult.subdomains.length;
      stats.liveIPs = reconResult.liveIPs.length;
      stats.emailsFound = reconResult.osint.emails.length;
      
      // Phase 2: Service Fingerprinting
      const services = await this.runFingerprinting(reconResult.liveIPs);
      stats.openPorts = services.length;
      
      // Phase 3: SSL/TLS Analysis
      if (this.config.sslEnabled) {
        await this.runSSLAnalysis(reconResult.liveIPs);
      }
      
      // Phase 4: Vulnerability Scanning
      let vulns: Vulnerability[] = [];
      if (this.config.vulnEnabled) {
        vulns = await this.runVulnScanning(services);
        stats.vulnsFound = vulns.length;
        stats.criticalVulns = vulns.filter(v => v.severity === 'critical').length;
      }
      
      // Phase 5-6: Exploitation & Post-Exploitation (simplified)
      await this.runExploitation(vulns);
      await this.runPostExploitation();
      
      // Phase 7: Reporting
      await this.runReporting(stats);
      
      return stats;
    } catch (error) {
      console.error('Scan error:', error);
      throw error;
    }
  }
}

// Helper function to create and start a scan
export async function createScan(
  target: string, 
  scope: string, 
  rateLimit: number, 
  config: ModuleConfig
): Promise<string> {
  const scan = await db.scan.create({
    data: {
      target,
      status: 'pending',
      progress: 0,
      scope,
      rateLimit,
    },
  });
  
  return scan.id;
}

// Update scan status
export async function updateScanStatus(
  scanId: string, 
  status: string, 
  progress: number, 
  currentPhase?: string
): Promise<void> {
  await db.scan.update({
    where: { id: scanId },
    data: {
      status,
      progress,
      currentPhase,
      ...(status === 'running' && { startedAt: new Date() }),
      ...(status === 'completed' && { completedAt: new Date() }),
    },
  });
}

// Get scan by ID
export async function getScan(scanId: string) {
  return db.scan.findUnique({
    where: { id: scanId },
    include: {
      reconResults: true,
      serviceResults: true,
      sslResults: true,
      vulnResults: true,
      report: true,
    },
  });
}

// Get all scans
export async function getAllScans() {
  return db.scan.findMany({
    orderBy: { createdAt: 'desc' },
    take: 50,
  });
}

// Delete scan and all related data
export async function deleteScan(scanId: string): Promise<void> {
  await db.scan.delete({
    where: { id: scanId },
  });
}

// Get scan statistics
export async function getScanStats(scanId: string) {
  const [serviceCount, sslCount, vulnCount, criticalCount] = await Promise.all([
    db.serviceResult.count({ where: { scanId } }),
    db.sSLResult.count({ where: { scanId } }),
    db.vulnerabilityResult.count({ where: { scanId } }),
    db.vulnerabilityResult.count({ where: { scanId, severity: 'critical' } }),
  ]);
  
  return {
    openPorts: serviceCount,
    sslHosts: sslCount,
    vulnsFound: vulnCount,
    criticalVulns: criticalCount,
  };
}
