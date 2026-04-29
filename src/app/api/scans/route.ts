import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { createScan, getAllScans } from '@/lib/services/scan-service';
import type { ModuleConfig } from '@/types/pentest';

// GET /api/scans - Get all scans
export async function GET() {
  try {
    const scans = await getAllScans();
    return NextResponse.json({ success: true, data: scans });
  } catch (error) {
    console.error('Error fetching scans:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to fetch scans' },
      { status: 500 }
    );
  }
}

// POST /api/scans - Create a new scan
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target, scope = 'full', rateLimit = 10, modules } = body;
    
    if (!target) {
      return NextResponse.json(
        { success: false, error: 'Target is required' },
        { status: 400 }
      );
    }
    
    // Default module configuration
    const defaultConfig: ModuleConfig = {
      whoisEnabled: true,
      dnsEnabled: true,
      subdomainEnabled: true,
      osintEnabled: true,
      shodanEnabled: false, // Requires API key
      asnEnabled: true,
      sslEnabled: true,
      vulnEnabled: true,
    };
    
    const config: ModuleConfig = modules ? { ...defaultConfig, ...modules } : defaultConfig;
    
    const scanId = await createScan(target, scope, rateLimit, config);
    
    // Log audit
    await db.auditLog.create({
      data: {
        action: 'scan_created',
        targetType: 'scan',
        targetId: scanId,
        details: JSON.stringify({ target, scope, rateLimit, config }),
      },
    });
    
    return NextResponse.json({ 
      success: true, 
      data: { scanId, message: 'Scan created successfully' } 
    });
  } catch (error) {
    console.error('Error creating scan:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to create scan' },
      { status: 500 }
    );
  }
}
