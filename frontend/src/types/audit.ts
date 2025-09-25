export interface IssueDetail {
  type: string
  line: number
  description: string
  severity: string
}

export interface SuspiciousFile {
  file_path: string
  language?: string
  issues: IssueDetail[]
  context?: Record<string, unknown>
}

export interface AIAnalysisSummary {
  raw_text: string
  summary: {
    risk_level: string
    vulnerability_count: number
  }
  vulnerabilities?: Array<{
    type: string
    severity: string
    description: string
  }>
  recommendations?: Array<{
    issue: string
    solution: string
  }>
}

export interface FileAIResult {
  issues: IssueDetail[]
  similar_code: Array<Record<string, unknown>>
  ai_analysis: {
    status?: string
    analysis?: AIAnalysisSummary
    message?: string
  }
}

export interface ProjectSummary {
  total_files: number
  suspicious_files: number
  total_issues: number
  risk_level: string
}

export interface ProjectAuditResult {
  status: string
  message?: string
  project_type?: string
  suspicious_files: SuspiciousFile[]
  ai_verification: Record<string, FileAIResult>
  summary: ProjectSummary
  recommendations: Array<{
    file: string
    issue: string
    solution: string
  }>
  project_path?: string
}

export interface SingleFileAuditResult {
  status: string
  message?: string
  issues: IssueDetail[]
  summary: ProjectSummary
  details: Record<string, unknown>
  recommendations: Array<{
    file: string
    issue: string
    solution: string
  }>
}

export type AuditResult = ProjectAuditResult | SingleFileAuditResult 