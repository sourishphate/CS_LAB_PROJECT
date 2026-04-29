import { NextRequest, NextResponse } from 'next/server';
import ZAI from 'z-ai-web-dev-sdk';
import { db } from '@/lib/db';

// PENTESTGPT System Prompts
const REASONING_MODULE_SYSTEM_PROMPT = `You are the Reasoning Module of a PENTESTGPT system, acting as a lead penetration tester.
Your role is to:
1. Maintain a high-level overview of the penetration testing status
2. Update the Pentesting Task Tree (PTT) based on execution results
3. Identify promising sub-tasks for testing
4. Direct subsequent actions based on testing results

When updating PTT:
- Mark completed tasks as "completed"
- Mark current task as "ongoing"
- Keep pending tasks as "to-do"
- Add new branches based on findings`;

const GENERATION_MODULE_SYSTEM_PROMPT = `You are the Generation Module of a PENTESTGPT system, acting as a junior penetration tester.
Your role is to:
1. Receive specific sub-tasks from the Reasoning Module
2. Expand sub-tasks into detailed steps using Chain-of-Thought (CoT) methodology
3. Generate precise terminal commands or GUI operation descriptions
4. Consider available tools and their correct usage`;

const PARSING_MODULE_SYSTEM_PROMPT = `You are the Parsing Module of a PENTESTGPT system.
Your role is to:
1. Process execution results and tool outputs
2. Extract essential information and identify findings
3. Condense verbose outputs while preserving key security information
4. Update context for the Reasoning Module`;

// POST /api/analyze/guided-step - Execute next step in guided testing
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { scanId, currentStep, executionResult } = body;

    if (!scanId) {
      return NextResponse.json(
        { success: false, error: 'Scan ID is required' },
        { status: 400 }
      );
    }

    // Get scan data
    const [scan, vulns, sslResults, services] = await Promise.all([
      db.scan.findUnique({ where: { id: scanId } }),
      db.vulnerabilityResult.findMany({ where: { scanId }, orderBy: { cvssScore: 'desc' } }),
      db.sSLResult.findMany({ where: { scanId } }),
      db.serviceResult.findMany({ where: { scanId } }),
    ]);

    if (!scan) {
      return NextResponse.json(
        { success: false, error: 'Scan not found' },
        { status: 404 }
      );
    }

    const zai = await ZAI.create();

    // Determine the current phase based on step number
    const phases = [
      { name: 'Service Enumeration', type: 'enumeration' },
      { name: 'Vulnerability Scanning', type: 'vulnscan' },
      { name: 'Exploitation Testing', type: 'exploitation' },
      { name: 'Post-Exploitation', type: 'postexploit' },
      { name: 'Reporting', type: 'reporting' }
    ];

    const currentPhase = phases[Math.min(currentStep, phases.length - 1)];

    // Module Messages
    const moduleMessages = {
      reasoning: [] as string[],
      generation: [] as string[],
      parsing: [] as string[]
    };

    // Step 1: Parsing Module - Process any execution results
    let parsedResult = '';
    if (executionResult) {
      const parsingPrompt = `Parse and analyze the following execution result:

${executionResult}

Extract:
1. Key findings (open ports, services, vulnerabilities, etc.)
2. Potential security issues
3. Interesting data points for further investigation
4. Recommended follow-up actions`;

      const parsingResponse = await zai.chat.completions.create({
        messages: [
          { role: 'system', content: PARSING_MODULE_SYSTEM_PROMPT },
          { role: 'user', content: parsingPrompt }
        ],
        temperature: 0.3,
        max_tokens: 1000,
      });

      parsedResult = parsingResponse.choices[0]?.message?.content || '';
      moduleMessages.parsing.push(parsedResult);
    }

    // Step 2: Reasoning Module - Update PTT and determine next task
    const reasoningPrompt = `Update the Pentesting Task Tree for target ${scan.target}.

Current Phase: ${currentPhase.name} (Step ${currentStep + 1})
Available Services: ${JSON.stringify(services.map((s: { port: number; service: string; version: string | null }) => ({ port: s.port, service: s.service, version: s.version })))}
Known Vulnerabilities: ${vulns.length} found
SSL Issues: ${sslResults.length} found

${parsedResult ? `Latest Parsing Results:\n${parsedResult}` : ''}

Create/Update PTT in JSON format:
{
  "id": "root",
  "task": "Penetration Test of ${scan.target}",
  "status": "ongoing",
  "children": [
    // Include completed, ongoing, and to-do tasks
  ]
}

Mark appropriate tasks as completed based on the current step.
Identify the next most promising task for execution.`;

    const reasoningResponse = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: REASONING_MODULE_SYSTEM_PROMPT },
        { role: 'user', content: reasoningPrompt }
      ],
      temperature: 0.4,
      max_tokens: 2000,
    });

    const reasoningContent = reasoningResponse.choices[0]?.message?.content || '';
    moduleMessages.reasoning.push(reasoningContent);

    // Extract PTT
    let taskTree = null;
    try {
      const jsonMatch = reasoningContent.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        taskTree = JSON.parse(jsonMatch[0]);
      }
    } catch {
      taskTree = createDefaultTaskTree(scan.target, currentStep);
    }

    // Step 3: Generation Module - Generate commands for current phase
    const generationPrompt = `Generate specific commands for the ${currentPhase.name} phase.

Target: ${scan.target}
Services: ${JSON.stringify(services.slice(0, 10), null, 2)}
Known Vulnerabilities: ${JSON.stringify(vulns.slice(0, 5).map((v: { title: string; severity: string; port: number | null }) => ({ title: v.title, severity: v.severity, port: v.port })), null, 2)}

Phase-specific requirements:
${getPhaseInstructions(currentPhase.type, services, vulns, sslResults)}

Generate 3-5 specific commands with:
- Exact command syntax
- Expected output format
- What to look for in results`;

    const generationResponse = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: GENERATION_MODULE_SYSTEM_PROMPT },
        { role: 'user', content: generationPrompt }
      ],
      temperature: 0.5,
      max_tokens: 1500,
    });

    const generationContent = generationResponse.choices[0]?.message?.content || '';
    moduleMessages.generation.push(generationContent);

    // Compile result
    const result = `## Step ${currentStep + 1}: ${currentPhase.name}

### Phase Context
${getPhaseDescription(currentPhase.type)}

### Generated Commands
${generationContent}

### Analysis Summary
${reasoningContent.slice(0, 500)}...

### Progress
- Completed Steps: ${currentStep}
- Current Phase: ${currentPhase.name}
- Remaining Phases: ${phases.length - currentStep - 1}`;

    return NextResponse.json({
      success: true,
      data: {
        result,
        taskTree,
        moduleMessages,
        currentPhase: currentPhase.name,
        stepNumber: currentStep + 1,
      },
    });

  } catch (error) {
    console.error('Guided step error:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to execute guided step' },
      { status: 500 }
    );
  }
}

function getPhaseInstructions(phase: string, services: unknown[], vulns: unknown[], sslResults: unknown[]): string {
  switch (phase) {
    case 'enumeration':
      return `- Enumerate service versions on all open ports
- Identify potential vulnerabilities based on service versions
- Check for default credentials on common services
- Enumerate web directories if HTTP/HTTPS services detected`;
    
    case 'vulnscan':
      return `- Run targeted vulnerability scanners
- Check for known CVEs in identified services
- Test SSL/TLS configurations
- Look for misconfigurations and weak settings`;
    
    case 'exploitation':
      return `- Test identified vulnerabilities
- Attempt exploitation with available tools
- Verify exploit success indicators
- Document exploitation attempts`;
    
    case 'postexploit':
      return `- Enumerate system information
- Check for privilege escalation opportunities
- Identify sensitive files and credentials
- Assess lateral movement possibilities`;
    
    case 'reporting':
      return `- Summarize findings
- Document evidence
- Create remediation recommendations
- Calculate risk scores`;
    
    default:
      return 'Continue with general penetration testing methodology.';
  }
}

function getPhaseDescription(phase: string): string {
  const descriptions: Record<string, string> = {
    enumeration: 'Detailed service enumeration and information gathering. Focus on identifying service versions, configurations, and potential attack vectors.',
    vulnscan: 'Vulnerability scanning and identification. Use automated and manual techniques to discover security weaknesses.',
    exploitation: 'Exploitation testing phase. Attempt to verify and exploit identified vulnerabilities.',
    postexploit: 'Post-exploitation activities. After gaining access, enumerate additional information and assess impact.',
    reporting: 'Final reporting phase. Document all findings, evidence, and recommendations.'
  };
  return descriptions[phase] || '';
}

function createDefaultTaskTree(target: string, step: number): unknown {
  const statuses = ['completed', 'ongoing', 'to-do', 'to-do', 'to-do'];
  return {
    id: 'root',
    task: `Penetration Test of ${target}`,
    status: 'ongoing',
    children: [
      { id: '1', task: 'Reconnaissance & Port Scanning', status: step > 0 ? 'completed' : 'ongoing', children: [] },
      { id: '2', task: 'Service Enumeration', status: statuses[step] || 'to-do', children: [] },
      { id: '3', task: 'Vulnerability Identification', status: step > 1 ? 'ongoing' : 'to-do', children: [] },
      { id: '4', task: 'Exploitation', status: step > 2 ? 'ongoing' : 'to-do', children: [] },
      { id: '5', task: 'Post-Exploitation', status: step > 3 ? 'ongoing' : 'to-do', children: [] },
      { id: '6', task: 'Reporting', status: step > 4 ? 'ongoing' : 'to-do', children: [] }
    ]
  };
}
