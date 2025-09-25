import re
from typing import List, Dict

class SecurityAnalyzer:
    def __init__(self):
        self.patterns = {
            'weak_crypto': [
                r'md5\(',
                r'sha1\(',
                r'crypt\(',
                r'des_encrypt\('
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*[\'\"][^\'\"]+[\'\"]',
                r'secret\s*=\s*[\'\"][^\'\"]+[\'\"]',
                r'api[_-]?key\s*=\s*[\'\"][^\'\"]+[\'\"]'
            ],
            'insecure_config': [
                r'display_errors\s*=\s*On',
                r'allow_url_include\s*=\s*On',
                r'register_globals\s*=\s*On'
            ],
            'csrf_vulnerability': [
                r'form.*method=[\'\"]post[\'\"].*(?!.*csrf)',
                r'ajax\.post\(.*(?!.*token)'
            ]
        }
        
    def analyze(self, code, file_type):
        """执行安全分析"""
        vulnerabilities = []
        
        if file_type == 'php':
            vulnerabilities.extend(self._analyze_php(code))
        elif file_type == 'java':
            vulnerabilities.extend(self._analyze_java(code))
            
        return vulnerabilities

    def _collect(self, code: str, rules: Dict[str, List[str]], default_severity: str = 'medium') -> List[Dict]:
        findings: List[Dict] = []
        lines = code.splitlines()
        for issue_type, patterns in rules.items():
            for pattern in patterns:
                for idx, line in enumerate(lines, 1):
                    if re.search(pattern, line, flags=re.I):
                        findings.append({
                            'type': issue_type,
                            'line': idx,
                            'description': f'matched pattern: {pattern}',
                            'severity': default_severity
                        })
        return findings

    def _analyze_php(self, code: str) -> List[Dict]:
        rules = {
            'weak_crypto': self.patterns['weak_crypto'],
            'hardcoded_secrets': self.patterns['hardcoded_secrets'],
            'insecure_config': self.patterns['insecure_config']
        }
        return self._collect(code, rules, default_severity='medium')

    def _analyze_java(self, code: str) -> List[Dict]:
        java_rules = {
            'sql_injection': [
                r'Statement\.execute(Query|Update)?\s*\(.*\+.*\)',
                r'PreparedStatement\s*\(.*\+.*\)'
            ],
            'command_injection': [
                r'Runtime\.exec\(.*\+.*\)',
                r'ProcessBuilder\(.*\+.*\)'
            ],
            'unsafe_redirects': [
                r'sendRedirect\(.*\+.*\)'
            ]
        }
        return self._collect(code, java_rules, default_severity='medium') 