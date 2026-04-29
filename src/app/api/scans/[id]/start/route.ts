import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { ScanService, updateScanStatus, getScan } from '@/lib/services/scan-service';
import type { ModuleConfig } from '@/types/pentest';

// POST /api/scans/[id]/start - Start a scan
export async function POST(
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
    
    if (scan.status === 'running') {
      return NextResponse.json(
        { success: false, error: 'Scan is already running' },
        { status: 400 }
      );
    }
    
    // Get module configuration from request or use defaults
    const body = await request.json().catch(() => ({}));
    const config: ModuleConfig = body.modules || {
      whoisEnabled: true,
      dnsEnabled: true,
      subdomainEnabled: true,
      osintEnabled: true,
      shodanEnabled: false,
      asnEnabled: true,
      sslEnabled: true,
      vulnEnabled: true,
    };
    
    // Start scan asynchronously
    runScanAsync(id, scan.target, config);
    
    return NextResponse.json({ 
      success: true, 
      message: 'Scan started' 
    });
  } catch (error) {
    console.error('Error starting scan:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to start scan' },
      { status: 500 }
    );
  }
}

// Async scan execution
async function runScanAsync(scanId: string, target: string, config: ModuleConfig) {
  const scanService = new ScanService(scanId, target, config);
  
  // Set up progress callback
  scanService.onUpdate(async (phase, progress, stats) => {
    try {
      await updateScanStatus(scanId, 'running', progress, phase);
      
      // Update attack surface nodes
      await db.attackSurfaceNode.upsert({
        where: { id: `${scanId}-progress` },
        create: {
          id: `${scanId}-progress`,
          scanId,
          nodeType: 'domain',
          label: `${phase}: ${progress}%`,
          data: JSON.stringify({ phase, progress, stats }),
        },
        update: {
          label: `${phase}: ${progress}%`,
          data: JSON.stringify({ phase, progress, stats }),
        },
      });
    } catch (err) {
      console.error('Error updating scan progress:', err);
    }
  });
  
  try {
    await updateScanStatus(scanId, 'running', 0, 'initializing');
    const stats = await scanService.runFullScan();
    await updateScanStatus(scanId, 'completed', 100, 'completed');
    
    // Log audit
    await db.auditLog.create({
      data: {
        action: 'scan_completed',
        targetType: 'scan',
        targetId: scanId,
        details: JSON.stringify(stats),
      },
    });
  } catch (error) {
    console.error('Scan failed:', error);
    await updateScanStatus(scanId, 'failed', 0, 'error');
    
    // Log audit
    await db.auditLog.create({
      data: {
        action: 'scan_failed',
        targetType: 'scan',
        targetId: scanId,
        details: JSON.stringify({ error: String(error) }),
      },
    });
  }
}
