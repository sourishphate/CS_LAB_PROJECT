'use client';

import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Brain, Sparkles, ShieldAlert, AlertTriangle, Bug, 
  Lightbulb, Zap, BarChart3, FileText, Target,
  GitBranch, Cpu, MessageSquare, ArrowRight, CheckCircle2,
  Circle, Play, RefreshCw, Network, Terminal
} from 'lucide-react';
import { toast } from 'sonner';
import ReactMarkdown from 'react-markdown';

// Loading Icon component
const LoadingIcon = ({ className }: { className?: string }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
  </svg>
);

interface AIAnalyticsProps {
  scanId: string | null;
  vulnerabilities: VulnerabilityResult[];
  sslResults: SSLResult[];
  services: ServiceResult[];
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

interface ServiceResult {
  ip: string;
  port: number;
  service: string;
  version: string | null;
  banner: string | null;
  os: string | null;
  cveFlags: string[];
}

interface PTTreeNode {
  id: string;
  task: string;
  status: 'completed' | 'ongoing' | 'to-do';
  children: PTTreeNode[];
  result?: string;
}

type AnalysisType = 
  | 'vulnerability_summary' 
  | 'security_recommendations' 
  | 'attack_vectors' 
  | 'executive_summary' 
  | 'remediation_plan'
  | 'pentestgpt_guided';

const ANALYSIS_OPTIONS: { type: AnalysisType; label: string; icon: React.ElementType; description: string }[] = [
  {
    type: 'pentestgpt_guided',
    label: 'PENTESTGPT Guided Testing',
    icon: GitBranch,
    description: 'AI-guided penetration testing with Task Tree methodology'
  },
  {
    type: 'vulnerability_summary',
    label: 'Vulnerability Summary',
    icon: Bug,
    description: 'AI-powered analysis of discovered vulnerabilities with risk assessment'
  },
  {
    type: 'security_recommendations',
    label: 'Security Recommendations',
    icon: ShieldAlert,
    description: 'Actionable security improvement suggestions'
  },
  {
    type: 'attack_vectors',
    label: 'Attack Vectors',
    icon: Target,
    description: 'Potential attack paths and exploitation scenarios'
  },
  {
    type: 'executive_summary',
    label: 'Executive Summary',
    icon: BarChart3,
    description: 'High-level overview for management and stakeholders'
  },
  {
    type: 'remediation_plan',
    label: 'Remediation Plan',
    icon: Lightbulb,
    description: 'Step-by-step guidance to fix vulnerabilities'
  }
];

// PENTESTGPT Three Module Icons
const ModuleIcon = ({ type }: { type: 'reasoning' | 'generation' | 'parsing' }) => {
  switch (type) {
    case 'reasoning':
      return <Brain className="h-5 w-5 text-blue-500" />;
    case 'generation':
      return <Terminal className="h-5 w-5 text-green-500" />;
    case 'parsing':
      return <MessageSquare className="h-5 w-5 text-purple-500" />;
  }
};

// Task Tree Node Component
const TaskTreeNode = ({ node, depth = 0 }: { node: PTTreeNode; depth?: number }) => {
  const getStatusIcon = () => {
    switch (node.status) {
      case 'completed':
        return <CheckCircle2 className="h-4 w-4 text-green-500" />;
      case 'ongoing':
        return <Play className="h-4 w-4 text-blue-500" />;
      default:
        return <Circle className="h-4 w-4 text-gray-400" />;
    }
  };

  return (
    <div className={`${depth > 0 ? 'ml-6 border-l-2 border-muted pl-3' : ''}`}>
      <div className="flex items-center gap-2 py-1.5">
        {getStatusIcon()}
        <span className={`text-sm ${node.status === 'completed' ? 'text-muted-foreground line-through' : node.status === 'ongoing' ? 'font-medium text-foreground' : 'text-muted-foreground'}`}>
          {node.task}
        </span>
        {node.status === 'ongoing' && (
          <Badge variant="outline" className="text-xs">Active</Badge>
        )}
      </div>
      {node.children.map((child, idx) => (
        <TaskTreeNode key={idx} node={child} depth={depth + 1} />
      ))}
    </div>
  );
};

export default function AIAnalytics({ scanId, vulnerabilities, sslResults, services }: AIAnalyticsProps) {
  const [loading, setLoading] = useState<AnalysisType | null>(null);
  const [result, setResult] = useState<{ type: AnalysisType; content: string } | null>(null);
  const [pttTree, setPttTree] = useState<PTTreeNode | null>(null);
  const [guidedStep, setGuidedStep] = useState<number>(0);
  const [moduleMessages, setModuleMessages] = useState<{
    reasoning: string[];
    generation: string[];
    parsing: string[];
  }>({ reasoning: [], generation: [], parsing: [] });

  const runAnalysis = async (analysisType: AnalysisType) => {
    if (!scanId) {
      toast.error('No scan selected. Please select a scan first.');
      return;
    }

    setLoading(analysisType);
    setResult(null);
    setPttTree(null);
    setGuidedStep(0);
    setModuleMessages({ reasoning: [], generation: [], parsing: [] });

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanId, analysisType }),
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error);
      }

      setResult({ type: analysisType, content: data.data.result });
      
      // If PENTESTGPT guided testing, parse the task tree
      if (analysisType === 'pentestgpt_guided' && data.data.taskTree) {
        setPttTree(data.data.taskTree);
        setModuleMessages(data.data.moduleMessages || { reasoning: [], generation: [], parsing: [] });
      }

      toast.success('Analysis complete');

    } catch (error) {
      toast.error(`Analysis failed: ${error}`);
    } finally {
      setLoading(null);
    }
  };

  const executeGuidedStep = async () => {
    if (!scanId || !pttTree) return;
    
    try {
      const response = await fetch('/api/analyze/guided-step', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanId, currentStep: guidedStep }),
      });

      const data = await response.json();

      if (data.success) {
        setGuidedStep(prev => prev + 1);
        setModuleMessages(prev => ({
          ...prev,
          ...data.data.moduleMessages
        }));
        if (data.data.taskTree) {
          setPttTree(data.data.taskTree);
        }
        setResult({ type: 'pentestgpt_guided', content: data.data.result });
      }
    } catch (error) {
      toast.error(`Step execution failed: ${error}`);
    }
  };

  if (!scanId) {
    return (
      <Card>
        <CardContent className="py-12">
          <div className="text-center text-muted-foreground">
            <Brain className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p className="text-lg font-medium">No Scan Selected</p>
            <p className="text-sm">Complete a scan or select one from history to use AI Analytics</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
  const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
  const sslIssues = sslResults.filter(s => s.riskRating === 'red' || s.isExpired || s.isSelfSigned).length;

  return (
    <div className="grid gap-6 lg:grid-cols-3">
      {/* Analysis Options */}
      <div className="lg:col-span-1 space-y-4">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Brain className="h-5 w-5 text-purple-500" />
              AI Analysis
            </CardTitle>
            <CardDescription>
              Select an analysis type to generate AI-powered insights
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {ANALYSIS_OPTIONS.map((option) => {
              const Icon = option.icon;
              const isLoading = loading === option.type;
              return (
                <Button
                  key={option.type}
                  variant={result?.type === option.type ? 'default' : 'outline'}
                  className="w-full justify-start h-auto py-3"
                  onClick={() => runAnalysis(option.type)}
                  disabled={loading !== null}
                >
                  <div className="flex items-start gap-3">
                    {isLoading ? (
                      <LoadingIcon className="h-5 w-5 animate-spin" />
                    ) : (
                      <Icon className="h-5 w-5 mt-0.5" />
                    )}
                    <div className="text-left">
                      <p className="font-medium">{option.label}</p>
                      <p className="text-xs text-muted-foreground">{option.description}</p>
                    </div>
                  </div>
                </Button>
              );
            })}
          </CardContent>
        </Card>

        {/* Quick Stats */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Scan Overview</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-sm text-muted-foreground">Total Vulnerabilities</span>
                <Badge variant="secondary">{vulnerabilities.length}</Badge>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-muted-foreground">Critical Issues</span>
                <Badge variant="destructive">{criticalCount}</Badge>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-muted-foreground">High Severity</span>
                <Badge className="bg-orange-500">{highCount}</Badge>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-muted-foreground">SSL/TLS Issues</span>
                <Badge variant={sslIssues > 0 ? 'destructive' : 'secondary'}>{sslIssues}</Badge>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-muted-foreground">Open Services</span>
                <Badge variant="secondary">{services.length}</Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Analysis Results */}
      <div className="lg:col-span-2">
        <Card className="h-full">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-yellow-500" />
              {result ? ANALYSIS_OPTIONS.find(o => o.type === result.type)?.label : 'Analysis Results'}
            </CardTitle>
            <CardDescription>
              {result 
                ? `Generated on ${new Date().toLocaleString()}`
                : 'Select an analysis type to see results'
              }
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex flex-col items-center justify-center py-12">
                <div className="relative">
                  <Brain className="h-16 w-16 text-purple-500 animate-pulse" />
                  <Sparkles className="h-6 w-6 text-yellow-500 absolute -top-1 -right-1 animate-bounce" />
                </div>
                <p className="mt-4 text-muted-foreground">Analyzing scan data...</p>
                <p className="text-sm text-muted-foreground">This may take a moment</p>
                
                {/* PENTESTGPT Module Activity */}
                {loading === 'pentestgpt_guided' && (
                  <div className="mt-6 grid grid-cols-3 gap-4 w-full max-w-md">
                    <div className="flex flex-col items-center p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
                      <Brain className="h-5 w-5 text-blue-500 animate-pulse" />
                      <span className="text-xs mt-1 text-blue-500">Reasoning</span>
                    </div>
                    <div className="flex flex-col items-center p-3 rounded-lg bg-green-500/10 border border-green-500/20">
                      <Terminal className="h-5 w-5 text-green-500 animate-pulse" />
                      <span className="text-xs mt-1 text-green-500">Generation</span>
                    </div>
                    <div className="flex flex-col items-center p-3 rounded-lg bg-purple-500/10 border border-purple-500/20">
                      <MessageSquare className="h-5 w-5 text-purple-500 animate-pulse" />
                      <span className="text-xs mt-1 text-purple-500">Parsing</span>
                    </div>
                  </div>
                )}
              </div>
            ) : result ? (
              result.type === 'pentestgpt_guided' ? (
                <Tabs defaultValue="overview" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="overview">Overview</TabsTrigger>
                    <TabsTrigger value="tasktree">Task Tree</TabsTrigger>
                    <TabsTrigger value="modules">Modules</TabsTrigger>
                    <TabsTrigger value="analysis">Analysis</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="overview" className="mt-4">
                    <div className="space-y-4">
                      {/* PENTESTGPT Architecture Overview */}
                      <div className="grid grid-cols-3 gap-4">
                        <Card className="border-blue-500/20 bg-blue-500/5">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <Brain className="h-4 w-4 text-blue-500" />
                              Reasoning Module
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <p className="text-xs text-muted-foreground">
                              Maintains high-level overview using Pentesting Task Tree (PTT). 
                              Acts as the lead tester, directing overall strategy.
                            </p>
                            <div className="mt-2 flex items-center gap-1">
                              <Badge variant="outline" className="text-xs">Lead Tester Role</Badge>
                            </div>
                          </CardContent>
                        </Card>
                        
                        <Card className="border-green-500/20 bg-green-500/5">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <Terminal className="h-4 w-4 text-green-500" />
                              Generation Module
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <p className="text-xs text-muted-foreground">
                              Constructs detailed procedures for specific sub-tasks. 
                              Mirrors junior tester role with precise command generation.
                            </p>
                            <div className="mt-2 flex items-center gap-1">
                              <Badge variant="outline" className="text-xs">Junior Tester Role</Badge>
                            </div>
                          </CardContent>
                        </Card>
                        
                        <Card className="border-purple-500/20 bg-purple-500/5">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm flex items-center gap-2">
                              <MessageSquare className="h-4 w-4 text-purple-500" />
                              Parsing Module
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <p className="text-xs text-muted-foreground">
                              Handles diverse text data: tool outputs, source codes, 
                              HTTP webpages. Extracts essential information.
                            </p>
                            <div className="mt-2 flex items-center gap-1">
                              <Badge variant="outline" className="text-xs">Data Processing</Badge>
                            </div>
                          </CardContent>
                        </Card>
                      </div>
                      
                      {/* Guided Testing Actions */}
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Guided Testing Session</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex items-center gap-4">
                            <Button onClick={executeGuidedStep} disabled={!pttTree}>
                              <Play className="h-4 w-4 mr-2" />
                              Execute Next Step
                            </Button>
                            <Button variant="outline" onClick={() => runAnalysis('pentestgpt_guided')}>
                              <RefreshCw className="h-4 w-4 mr-2" />
                              Restart Session
                            </Button>
                            <span className="text-sm text-muted-foreground">
                              Step {guidedStep + 1}
                            </span>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="tasktree" className="mt-4">
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm flex items-center gap-2">
                          <GitBranch className="h-4 w-4" />
                          Pentesting Task Tree (PTT)
                        </CardTitle>
                        <CardDescription>
                          Real-time representation of the testing process status
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        {pttTree ? (
                          <ScrollArea className="h-[400px]">
                            <TaskTreeNode node={pttTree} />
                          </ScrollArea>
                        ) : (
                          <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                            <Network className="h-10 w-10 mb-2 opacity-50" />
                            <p>Start a guided session to generate the Task Tree</p>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  </TabsContent>
                  
                  <TabsContent value="modules" className="mt-4">
                    <div className="grid grid-cols-3 gap-4">
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm flex items-center gap-2">
                            <Brain className="h-4 w-4 text-blue-500" />
                            Reasoning Module
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ScrollArea className="h-[300px]">
                            {moduleMessages.reasoning.length > 0 ? (
                              <div className="space-y-2">
                                {moduleMessages.reasoning.map((msg, idx) => (
                                  <div key={idx} className="p-2 rounded bg-muted text-xs">
                                    {msg}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-muted-foreground text-xs">No messages yet</p>
                            )}
                          </ScrollArea>
                        </CardContent>
                      </Card>
                      
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm flex items-center gap-2">
                            <Terminal className="h-4 w-4 text-green-500" />
                            Generation Module
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ScrollArea className="h-[300px]">
                            {moduleMessages.generation.length > 0 ? (
                              <div className="space-y-2">
                                {moduleMessages.generation.map((msg, idx) => (
                                  <div key={idx} className="p-2 rounded bg-muted text-xs font-mono">
                                    {msg}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-muted-foreground text-xs">No messages yet</p>
                            )}
                          </ScrollArea>
                        </CardContent>
                      </Card>
                      
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm flex items-center gap-2">
                            <MessageSquare className="h-4 w-4 text-purple-500" />
                            Parsing Module
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ScrollArea className="h-[300px]">
                            {moduleMessages.parsing.length > 0 ? (
                              <div className="space-y-2">
                                {moduleMessages.parsing.map((msg, idx) => (
                                  <div key={idx} className="p-2 rounded bg-muted text-xs">
                                    {msg}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-muted-foreground text-xs">No messages yet</p>
                            )}
                          </ScrollArea>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="analysis" className="mt-4">
                    <ScrollArea className="h-[500px]">
                      <div className="prose prose-sm dark:prose-invert max-w-none">
                        <ReactMarkdown
                          components={{
                            h1: ({ children }) => <h1 className="text-xl font-bold mb-4 text-foreground">{children}</h1>,
                            h2: ({ children }) => <h2 className="text-lg font-semibold mb-3 mt-6 text-foreground">{children}</h2>,
                            h3: ({ children }) => <h3 className="text-base font-medium mb-2 mt-4 text-foreground">{children}</h3>,
                            p: ({ children }) => <p className="mb-3 text-muted-foreground leading-relaxed">{children}</p>,
                            ul: ({ children }) => <ul className="list-disc list-inside mb-3 space-y-1 text-muted-foreground">{children}</ul>,
                            ol: ({ children }) => <ol className="list-decimal list-inside mb-3 space-y-1 text-muted-foreground">{children}</ol>,
                            li: ({ children }) => <li className="ml-2">{children}</li>,
                            strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
                            code: ({ children }) => <code className="bg-muted px-1.5 py-0.5 rounded text-sm font-mono">{children}</code>,
                            blockquote: ({ children }) => <blockquote className="border-l-4 border-primary pl-4 italic text-muted-foreground">{children}</blockquote>,
                          }}
                        >
                          {result.content}
                        </ReactMarkdown>
                      </div>
                    </ScrollArea>
                  </TabsContent>
                </Tabs>
              ) : (
                <ScrollArea className="h-[600px]">
                  <div className="prose prose-sm dark:prose-invert max-w-none">
                    <ReactMarkdown
                      components={{
                        h1: ({ children }) => <h1 className="text-xl font-bold mb-4 text-foreground">{children}</h1>,
                        h2: ({ children }) => <h2 className="text-lg font-semibold mb-3 mt-6 text-foreground">{children}</h2>,
                        h3: ({ children }) => <h3 className="text-base font-medium mb-2 mt-4 text-foreground">{children}</h3>,
                        p: ({ children }) => <p className="mb-3 text-muted-foreground leading-relaxed">{children}</p>,
                        ul: ({ children }) => <ul className="list-disc list-inside mb-3 space-y-1 text-muted-foreground">{children}</ul>,
                        ol: ({ children }) => <ol className="list-decimal list-inside mb-3 space-y-1 text-muted-foreground">{children}</ol>,
                        li: ({ children }) => <li className="ml-2">{children}</li>,
                        strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
                        code: ({ children }) => <code className="bg-muted px-1.5 py-0.5 rounded text-sm font-mono">{children}</code>,
                        blockquote: ({ children }) => <blockquote className="border-l-4 border-primary pl-4 italic text-muted-foreground">{children}</blockquote>,
                      }}
                    >
                      {result.content}
                    </ReactMarkdown>
                  </div>
                </ScrollArea>
              )
            ) : (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Zap className="h-12 w-12 mb-4 opacity-50" />
                <p className="text-lg font-medium">Ready for Analysis</p>
                <p className="text-sm">Choose an analysis type from the left panel</p>
                <div className="mt-6 grid grid-cols-2 gap-4 text-center">
                  <div className="p-4 rounded-lg bg-muted/50">
                    <p className="text-2xl font-bold text-foreground">{vulnerabilities.length}</p>
                    <p className="text-xs">Vulnerabilities to analyze</p>
                  </div>
                  <div className="p-4 rounded-lg bg-muted/50">
                    <p className="text-2xl font-bold text-foreground">{services.length}</p>
                    <p className="text-xs">Services discovered</p>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
