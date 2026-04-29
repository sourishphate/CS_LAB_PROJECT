import { NextRequest, NextResponse } from 'next/server';
import { getScan, deleteScan } from '@/lib/services/scan-service';

// GET /api/scans/[id] - Get scan by ID
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
    
    return NextResponse.json({ success: true, data: scan });
  } catch (error) {
    console.error('Error fetching scan:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to fetch scan' },
      { status: 500 }
    );
  }
}

// DELETE /api/scans/[id] - Delete scan
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    await deleteScan(id);
    return NextResponse.json({ success: true, message: 'Scan deleted' });
  } catch (error) {
    console.error('Error deleting scan:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to delete scan' },
      { status: 500 }
    );
  }
}
