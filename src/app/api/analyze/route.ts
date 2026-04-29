import { NextRequest, NextResponse } from 'next/server';
import { GoogleGenerativeAI } from "@google/generative-ai";
import { db } from '@/lib/db';

// Initialize Gemini
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY!);

// ---------------- SYSTEM PROMPTS ----------------

const REASONING_MODULE_SYSTEM_PROMPT = `You are the Reasoning Module of a PENTESTGPT system, acting as a lead penetration tester.
Your role is to:
1. Maintain a high-level overview of the penetration testing status
2. Create and manage the Pentesting Task Tree (PTT) - a tree structure encoding the testing process status
3. Identify promising sub-tasks for testing
4. Direct subsequent actions based on testing results

The PTT is organized as follows:
- Root: The main testing objective
- Children: Sub-tasks like port scanning, service enumeration, vulnerability identification
- Leaf nodes: Specific operations like "scan port 80" or "test anonymous FTP login"

PTT Node States:
- completed: Task finished successfully
- ongoing: Currently being executed
- to-do: Pending execution

Output your PTT in a structured format that can be parsed. Always think step-by-step and consider the holistic view of the penetration test.`;

const GENERATION_MODULE_SYSTEM_PROMPT = `You are the Generation Module of a PENTESTGPT system, acting as a junior penetration tester.
Your role is to:
1. Receive specific sub-tasks from the Reasoning Module
2. Expand sub-tasks into detailed steps using Chain-of-Thought (CoT) methodology
3. Generate precise terminal commands or GUI operation descriptions
4. Consider available tools and their correct usage

When generating commands:
- Specify exact flags and parameters
- Consider the target environment
- Provide clear execution instructions
- Include expected output descriptions

Always be precise and avoid hallucinations. If uncertain, state limitations clearly.`;

const PARSING_MODULE_SYSTEM_PROMPT = `You are the Parsing Module of a PENTESTGPT system.
Your role is to:
1. Process diverse text data: tool outputs, source codes, HTTP webpages
2. Extract essential information and condense verbose outputs
3. Emphasize security-relevant findings
4. Use token compression techniques to manage context

Categories of input:
1. Security tool outputs (nmap, nikto, sqlmap, etc.)
2. Source code snippets
3. Raw HTTP web information
4. Configuration files

Extract: open ports, services, versions, potential vulnerabilities, interesting endpoints, credentials/keys, and any actionable intelligence.`;

// ---------------- GEMINI HELPER ----------------

async function runGemini(
  systemPrompt: string,
  userPrompt: string,
  temperature = 0.5,
  maxTokens = 2000
) {
  const model = genAI.getGenerativeModel({
    model: "gemini-3-flash-preview",
    generationConfig: {
      temperature,
      maxOutputTokens: maxTokens,
    }
  });

  const result = await model.generateContent(
    `${systemPrompt}\n\n${userPrompt}`
  );

  return result.response.text();
}

// ---------------- API HANDLER ----------------

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { scanId, analysisType } = body;

    if (!scanId) {
      return NextResponse.json(
        { success: false, error: 'Scan ID is required' },
        { status: 400 }
      );
    }

    const [scan, vulns, sslResults, services, recon] = await Promise.all([
      db.scan.findUnique({ where: { id: scanId } }),
      db.vulnerabilityResult.findMany({ 
        where: { scanId },
        orderBy: { cvssScore: 'desc' },
        take: 10
      }),
      db.sSLResult.findMany({ where: { scanId } }),
      db.serviceResult.findMany({ where: { scanId } }),
      db.reconResult.findUnique({ where: { scanId } }),
    ]);

    if (!scan) {
      return NextResponse.json(
        { success: false, error: 'Scan not found' },
        { status: 404 }
      );
    }

    let result = '';
    let taskTree = null;
    let moduleMessages = { reasoning: [] as string[], generation: [] as string[], parsing: [] as string[] };

    switch (analysisType) {
      case 'pentestgpt_guided':
        const guidedResult = await runPENTESTGPTGuided(scan, vulns, sslResults, services, recon);
        result = guidedResult.result;
        taskTree = guidedResult.taskTree;
        moduleMessages = guidedResult.moduleMessages;
        break;

      case 'vulnerability_summary':
        result = await analyzeWithLLM(buildVulnerabilityPrompt(vulns, scan.target));
        break;

      case 'security_recommendations':
        result = await analyzeWithLLM(buildRecommendationsPrompt(vulns, sslResults, services, scan.target));
        break;

      case 'attack_vectors':
        result = await analyzeWithLLM(buildAttackVectorsPrompt(vulns, services, scan.target));
        break;

      case 'executive_summary':
        result = await analyzeWithLLM(buildExecutiveSummaryPrompt(scan, vulns, sslResults, services, recon));
        break;

      case 'remediation_plan':
        result = await analyzeWithLLM(buildRemediationPrompt(vulns));
        break;

      default:
        result = await analyzeWithLLM(buildGeneralAnalysisPrompt(scan, vulns, sslResults, services));
    }

    await db.auditLog.create({
      data: {
        action: 'llm_analysis',
        targetType: 'scan',
        targetId: scanId,
        details: JSON.stringify({ analysisType, timestamp: new Date().toISOString() }),
      },
    });

    return NextResponse.json({
      success: true,
      data: {
        analysisType,
        result,
        taskTree,
        moduleMessages,
        generatedAt: new Date().toISOString(),
      },
    });

  } catch (error) {
    console.error('LLM Analysis error:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to analyze with LLM' },
      { status: 500 }
    );
  }
}

// ---------------- PENTESTGPT ----------------

async function runPENTESTGPTGuided(
  scan: { target: string; createdAt: Date },
  vulns: unknown[],
  sslResults: unknown[],
  services: unknown[],
  recon: unknown
) {
  const moduleMessages = {
    reasoning: [] as string[],
    generation: [] as string[],
    parsing: [] as string[]
  };

  // Parsing
  const parsingPrompt = `Analyze the following scan data and extract key security information:

Target: ${scan.target}
Services: ${JSON.stringify(services, null, 2)}
Vulnerabilities: ${JSON.stringify(vulns.slice(0, 5), null, 2)}
SSL/TLS Issues: ${JSON.stringify(sslResults, null, 2)}`;

  const parsedInfo = await runGemini(PARSING_MODULE_SYSTEM_PROMPT, parsingPrompt, 0.3);
  moduleMessages.parsing.push(parsedInfo);

  // Reasoning
  const reasoningPrompt = `Based on the parsed information, create a Pentesting Task Tree (PTT) for target ${scan.target}.

Parsed Information:
${parsedInfo}`;

  const reasoningResponse = await runGemini(REASONING_MODULE_SYSTEM_PROMPT, reasoningPrompt, 0.4);
  moduleMessages.reasoning.push(reasoningResponse);

  let taskTree = null;
  try {
    const jsonMatch = reasoningResponse.match(/\{[\s\S]*\}/);
    if (jsonMatch) taskTree = JSON.parse(jsonMatch[0]);
  } catch {
    taskTree = { id: 'root', task: 'Pentest', status: 'ongoing' };
  }

  // Generation
  const generationPrompt = `Based on the current penetration testing status, generate commands.

Target: ${scan.target}
TaskTree: ${JSON.stringify(taskTree)}`;

  const generationResponse = await runGemini(GENERATION_MODULE_SYSTEM_PROMPT, generationPrompt, 0.5);
  moduleMessages.generation.push(generationResponse);

  const result = `# PENTESTGPT Guided Analysis Report

## Target: ${scan.target}

### Parsing
${parsedInfo}

### Reasoning
${reasoningResponse}

### Commands
${generationResponse}`;

  return { result, taskTree, moduleMessages };
}

// ---------------- GENERIC ANALYSIS ----------------

async function analyzeWithLLM(prompt: string): Promise<string> {
  return runGemini(
    `You are a senior cybersecurity analyst and penetration tester.`,
    prompt,
    0.7
  );
}

// ---------------- PROMPTS ----------------

function buildVulnerabilityPrompt(vulns: unknown[], target: string): string {
  return `Analyze vulnerabilities on ${target}:\n${JSON.stringify(vulns, null, 2)}`;
}

function buildRecommendationsPrompt(vulns: unknown[], sslResults: unknown[], services: unknown[], target: string): string {
  return `Recommendations for ${target}`;
}

function buildAttackVectorsPrompt(vulns: unknown[], services: unknown[], target: string): string {
  return `Attack vectors for ${target}`;
}

function buildExecutiveSummaryPrompt(scan: any, vulns: unknown[], sslResults: unknown[], services: unknown[], recon: unknown): string {
  return `Executive summary for ${scan.target}`;
}

function buildRemediationPrompt(vulns: unknown[]): string {
  return `Remediation plan:\n${JSON.stringify(vulns, null, 2)}`;
}

function buildGeneralAnalysisPrompt(scan: any, vulns: unknown[], sslResults: unknown[], services: unknown[]): string {
  return `General analysis for ${scan.target}`;
}