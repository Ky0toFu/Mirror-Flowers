import re

class FrameworkAnalyzer:
    def __init__(self):
        self.framework_rules = {
            'spring': {
                'security_checks': {
                    'csrf': [
                        r'@EnableWebSecurity(?!.*csrf\(\)\.disable\(\))',
                        r'csrf\(\)\.disable\(\)'
                    ],
                    'auth': [
                        r'@PreAuthorize',
                        r'@Secured',
                        r'SecurityContextHolder'
                    ],
                    'cors': [
                        r'@CrossOrigin\(.*allowCredentials\s*=\s*true.*\)',
                        r'addCorsMappings\('
                    ]
                },
                'dangerous_configs': [
                    r'security\.basic\.enabled\s*=\s*false',
                    r'management\.security\.enabled\s*=\s*false'
                ]
            },
            'django': {
                'security_checks': {
                    'csrf': [
                        r'@csrf_exempt',
                        r'CSRF_COOKIE_SECURE\s*=\s*False'
                    ],
                    'auth': [
                        r'@login_required',
                        r'@permission_required'
                    ],
                    'xss': [
                        r'mark_safe\(',
                        r'safe\s+filter'
                    ]
                },
                'dangerous_configs': [
                    r'DEBUG\s*=\s*True',
                    r'ALLOWED_HOSTS\s*=\s*\[\s*\'\*\'\s*\]'
                ]
            },
            'express': {
                'security_checks': {
                    'helmet': [
                        r'app\.use\(helmet\(\)\)',
                        r'app\.use\(cors\(\)\)'
                    ],
                    'auth': [
                        r'passport\.authenticate',
                        r'jwt\.verify'
                    ],
                    'input': [
                        r'body-parser',
                        r'express-validator'
                    ]
                },
                'dangerous_configs': [
                    r'app\.disable\(.*trust\s*proxy.*\)',
                    r'app\.use\(bodyParser\.raw\(\)\)'
                ]
            },
            'hibernate': {
                'security_checks': {
                    'sql': [
                        r'createQuery\(.*\+.*\)',
                        r'createSQLQuery\(.*\+.*\)'
                    ],
                    'cache': [
                        r'@Cache\(',
                        r'setCacheable\('
                    ],
                    'validation': [
                        r'@Valid',
                        r'@Validated'
                    ]
                },
                'dangerous_configs': [
                    r'show_sql\s*=\s*true',
                    r'hibernate\.format_sql\s*=\s*true'
                ]
            }
        }

    def analyze_framework(self, code: str, framework: str) -> dict:
        """分析框架特定的安全问题"""
        if framework not in self.framework_rules:
            return {"error": f"不支持的框架: {framework}"}

        issues = []
        rules = self.framework_rules[framework]

        # 检查安全配置
        for check_type, patterns in rules['security_checks'].items():
            for pattern in patterns:
                matches = re.finditer(pattern, code)
                for match in matches:
                    issues.append({
                        'type': f'{framework}_{check_type}_issue',
                        'pattern': pattern,
                        'location': self._get_location(code, match.start()),
                        'description': self._get_issue_description(framework, check_type, pattern),
                        'severity': self._calculate_severity(framework, check_type)
                    })

        # 检查危险配置
        for pattern in rules['dangerous_configs']:
            matches = re.finditer(pattern, code)
            for match in matches:
                issues.append({
                    'type': f'{framework}_dangerous_config',
                    'pattern': pattern,
                    'location': self._get_location(code, match.start()),
                    'description': f'发现危险的{framework}配置',
                    'severity': 'high'
                })

        return {
            'framework': framework,
            'issues': issues,
            'analysis_summary': self._generate_summary(issues)
        }

    def _get_location(self, code: str, pos: int) -> dict:
        """获取代码位置信息"""
        lines = code[:pos].splitlines()
        return {
            'line': len(lines),
            'column': len(lines[-1]) if lines else 0
        }

    def _calculate_severity(self, framework: str, check_type: str) -> str:
        """计算问题严重程度"""
        high_severity = {
            'spring': ['csrf', 'auth'],
            'django': ['csrf', 'auth'],
            'express': ['helmet', 'auth'],
            'hibernate': ['sql']
        }
        
        if framework in high_severity and check_type in high_severity[framework]:
            return 'high'
        return 'medium'

    def _get_issue_description(self, framework: str, check_type: str, pattern: str) -> str:
        """获取问题描述"""
        descriptions = {
            'spring': {
                'csrf': 'Spring Security CSRF 保护配置问题',
                'auth': 'Spring Security 认证授权配置问题',
                'cors': 'Spring CORS 配置可能存在安全风险'
            },
            'django': {
                'csrf': 'Django CSRF 保护被禁用',
                'auth': 'Django 认证装饰器使用不当',
                'xss': 'Django XSS 防护被绕过'
            },
            'express': {
                'helmet': 'Express 安全中间件配置问题',
                'auth': 'Express 认证机制实现问题',
                'input': 'Express 输入验证配置问题'
            },
            'hibernate': {
                'sql': 'Hibernate SQL 注入风险',
                'cache': 'Hibernate 缓存配置问题',
                'validation': 'Hibernate 验证配置问题'
            }
        }
        
        return descriptions.get(framework, {}).get(check_type, '未知问题')

    def _generate_summary(self, issues: list) -> str:
        """生成分析总结"""
        if not issues:
            return "未发现框架相关的安全问题"
            
        summary = "框架安全分析总结:\n"
        severity_count = {'high': 0, 'medium': 0, 'low': 0}
        
        for issue in issues:
            severity_count[issue['severity']] += 1
            
        summary += f"- 高危问题: {severity_count['high']} 个\n"
        summary += f"- 中危问题: {severity_count['medium']} 个\n"
        summary += f"- 低危问题: {severity_count['low']} 个\n"
        
        return summary 