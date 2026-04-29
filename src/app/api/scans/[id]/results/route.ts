import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { getScan } from '@/lib/services/scan-service';

// GET /api/scans/[id]/results - Get scan results
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const scan = await getScan(id);
    
    if (!scan) {
      return NextResponse.json(
        { success: false, error: 'Scan not found' },
        { status: 404 }
      );
    }
    
    // Get all results
    const [reconResults, serviceResults, sslResults, vulnResults, attackSurface] = await Promise.all([
      db.reconResult.findUnique({ where: { scanId: id } }),
      db.serviceResult.findMany({ where: { scanId: id } }),
      db.sSLResult.findMany({ where: { scanId: id } }),
      db.vulnerabilityResult.findMany({ 
        where: { scanId: id },
        orderBy: { cvssScore: 'desc' }
      }),
      db.attackSurfaceNode.findMany({ where: { scanId: id } }),
    ]);
    
    // Parse JSON fields
    const parsedRecon = reconResults ? {
      ...reconResults,
      whoisData: reconResults.whoisData ? JSON.parse(reconResults.whoisData) : null,
      dnsRecords: reconResults.dnsRecords ? JSON.parse(reconResults.dnsRecords) : [],
      subdomains: reconResults.subdomains ? JSON.parse(reconResults.subdomains) : [],
      emails: reconResults.emails ? JSON.parse(reconResults.emails) : [],
      names: reconResults.names ? JSON.parse(reconResults.names) : [],
      asnData: reconResults.asnData ? JSON.parse(reconResults.asnData) : [],
      liveIPs: reconResults.liveIPs ? JSON.parse(reconResults.liveIPs) : [],
    } : null;
    
    const parsedServices = serviceResults.map(s => ({
      ...s,
      cveFlags: s.cveFlags ? JSON.parse(s.cveFlags) : [],
    }));
    
    const parsedVulns = vulnResults.map(v => ({
      ...v,
      references: v.references ? JSON.parse(v.references) : [],
    }));
    
    // Build attack surface graph
    const graph = buildAttackSurfaceGraph(
      parsedRecon,
      parsedServices,
      sslResults,
      parsedVulns
    );
    
    return NextResponse.json({
      success: true,
      data: {
        scan,
        recon: parsedRecon,
        services: parsedServices,
        ssl: sslResults,
        vulnerabilities: parsedVulns,
        attackSurface: graph,
        stats: {
          subdomainsFound: parsedRecon?.subdomains?.length || 0,
          liveIPs: parsedRecon?.liveIPs?.length || 0,
          emailsFound: parsedRecon?.emails?.length || 0,
          openPorts: parsedServices.length,
          vulnsFound: parsedVulns.length,
          criticalVulns: parsedVulns.filter(v => v.severity === 'critical').length,
        },
      },
    });
  } catch (error) {
    console.error('Error fetching results:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to fetch results' },
      { status: 500 }
    );
  }
}

// Build attack surface graph
function buildAttackSurfaceGraph(
  recon: { subdomains: { name: string; ip: string | null }[]; liveIPs: string[] } | null,
  services: { ip: string; port: number; service: string; version: string | null }[],
  ssl: { host: string; riskRating: string }[],
  vulns: { cveId: string; host: string; severity: string }[]
) {
  const nodes: { id: string; type: string; label: string; data: Record<string, unknown> }[] = [];
  const edges: { source: string; target: string; label?: string }[] = [];
  
  if (!recon) return { nodes, edges };
  
  // Add domain nodes
  const mainDomain = recon.subdomains[0]?.name?.split('.').slice(-2).join('.');
  if (mainDomain) {
    nodes.push({
      id: `domain-${mainDomain}`,
      type: 'domain',
      label: mainDomain,
      data: { type: 'domain' },
    });
  }
  
  // Add subdomain nodes
  recon.subdomains.forEach((sub, i) => {
    nodes.push({
      id: `subdomain-${i}`,
      type: 'domain',
      label: sub.name,
      data: { ip: sub.ip, status: sub.ip ? 'live' : 'dead' },
    });
    
    if (mainDomain) {
      edges.push({
        source: `domain-${mainDomain}`,
        target: `subdomain-${i}`,
        label: 'subdomain',
      });
    }
    
    // Add IP nodes
    if (sub.ip) {
      const ipNodeId = `ip-${sub.ip}`;
      if (!nodes.find(n => n.id === ipNodeId)) {
        nodes.push({
          id: ipNodeId,
          type: 'ip',
          label: sub.ip,
          data: {},
        });
      }
      
      edges.push({
        source: `subdomain-${i}`,
        target: ipNodeId,
        label: 'resolves to',
      });
    }
  });
  
  // Add service nodes
  services.forEach((svc, i) => {
    nodes.push({
      id: `service-${i}`,
      type: 'service',
      label: `${svc.service}:${svc.port}`,
      data: { ip: svc.ip, port: svc.port, version: svc.version },
    });
    
    edges.push({
      source: `ip-${svc.ip}`,
      target: `service-${i}`,
      label: 'runs',
    });
  });
  
  // Add vulnerability nodes
  vulns.forEach((vuln, i) => {
    nodes.push({
      id: `vuln-${i}`,
      type: 'vuln',
      label: vuln.cveId,
      data: { severity: vuln.severity, host: vuln.host },
    });
    
    edges.push({
      source: `ip-${vuln.host}`,
      target: `vuln-${i}`,
      label: 'vulnerable',
    });
  });
  
  return { nodes, edges };
}
