import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { getScan } from '@/lib/services/scan-service';

// GET /api/scans/[id]/report - Get or export scan report
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const { searchParams } = new URL(request.url);
    const format = searchParams.get('format') || 'json'; // json or pdf
    
    const scan = await getScan(id);
    
    if (!scan) {
      return NextResponse.json(
        { success: false, error: 'Scan not found' },
        { status: 404 }
      );
    }
    
    // Get all results for report
    const [reconResults, serviceResults, sslResults, vulnResults, report] = await Promise.all([
      db.reconResult.findUnique({ where: { scanId: id } }),
      db.serviceResult.findMany({ where: { scanId: id } }),
      db.sSLResult.findMany({ where: { scanId: id } }),
      db.vulnerabilityResult.findMany({ 
        where: { scanId: id },
        orderBy: { cvssScore: 'desc' }
      }),
      db.report.findUnique({ where: { scanId: id } }),
    ]);
    
    if (format === 'json') {
      const fullReport = {
        meta: {
          scanId: id,
          target: scan.target,
          scanDate: scan.createdAt,
          completedAt: scan.completedAt,
          status: scan.status,
        },
        summary: report ? {
          totalHosts: report.totalHosts,
          totalPorts: report.totalPorts,
          totalVulns: report.totalVulns,
          criticalVulns: report.criticalVulns,
          highVulns: report.highVulns,
          mediumVulns: report.mediumVulns,
          lowVulns: report.lowVulns,
          riskScore: report.riskScore,
          compliance: report.complianceData ? JSON.parse(report.complianceData) : null,
        } : null,
        reconnaissance: reconResults ? {
          whois: reconResults.whoisData ? JSON.parse(reconResults.whoisData) : null,
          dnsRecords: reconResults.dnsRecords ? JSON.parse(reconResults.dnsRecords) : [],
          subdomains: reconResults.subdomains ? JSON.parse(reconResults.subdomains) : [],
          emails: reconResults.emails ? JSON.parse(reconResults.emails) : [],
          liveIPs: reconResults.liveIPs ? JSON.parse(reconResults.liveIPs) : [],
        } : null,
        services: serviceResults.map(s => ({
          ip: s.ip,
          port: s.port,
          service: s.service,
          version: s.version,
          os: s.os,
          cveFlags: s.cveFlags ? JSON.parse(s.cveFlags) : [],
        })),
        ssl: sslResults.map(s => ({
          host: s.host,
          port: s.port,
          issuer: s.issuer,
          protocol: s.protocol,
          cipherSuite: s.cipherSuite,
          riskRating: s.riskRating,
          isExpired: s.isExpired,
          isSelfSigned: s.isSelfSigned,
          daysRemaining: s.daysRemaining,
        })),
        vulnerabilities: vulnResults.map(v => ({
          cveId: v.cveId,
          title: v.title,
          host: v.host,
          port: v.port,
          cvssScore: v.cvssScore,
          severity: v.severity,
          exploitAvailable: v.exploitAvailable,
          status: v.status,
        })),
      };
      
      // Log audit
      await db.auditLog.create({
        data: {
          action: 'report_exported',
          targetType: 'scan',
          targetId: id,
          details: JSON.stringify({ format: 'json' }),
        },
      });
      
      return new NextResponse(JSON.stringify(fullReport, null, 2), {
        headers: {
          'Content-Type': 'application/json',
          'Content-Disposition': `attachment; filename="pentest-report-${id}.json"`,
        },
      });
    }
    
    // For PDF format, return a message (PDF generation would require additional setup)
    return NextResponse.json({
      success: true,
      message: 'PDF export requires additional setup. Use JSON format for now.',
      data: {
        reportId: report?.id,
        riskScore: report?.riskScore,
      },
    });
    
  } catch (error) {
    console.error('Error generating report:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to generate report' },
      { status: 500 }
    );
  }
}
