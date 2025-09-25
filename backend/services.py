from core.analyzers import CoreAnalyzer
from core.database import CodeVectorStore
from .config import settings, paths
import logging
from typing import Dict, Any, List, Optional
import asyncio
from openai import AsyncOpenAI
import json
from pathlib import Path
import os
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class CodeAuditService:
    def __init__(self):
        self.core_analyzer = None
        self.vector_store = None
        self.openai_api_key = settings.OPENAI_API_KEY
        self.api_base = settings.OPENAI_API_BASE
        self.model = settings.OPENAI_MODEL
        self.config_file = paths.config_dir / "api_config.json"
        
        self._runtime_api_key: Optional[str] = None
        self._runtime_api_base: Optional[str] = None
        self._runtime_model: Optional[str] = None
        
    async def ensure_initialized(self):
        """确保服务已初始化"""
        try:
            # 加载保存的配置
            await self.load_config()
            
            # 如果有配置，验证并更新模型
            if self.openai_api_key and self.api_base:
                try:
                    # 规范化 API 基础 URL（按提供商）
                    self.api_base = self._normalize_base_url(self.api_base)
                    
                    client = AsyncOpenAI(
                        api_key=self.openai_api_key,
                        base_url=self.api_base
                    )
                    models_response = await client.models.list()
                    available_models = [m.id for m in models_response.data]
                    
                    # 验证当前模型
                    if not self.model or self.model not in available_models:
                        # 选择一个默认的可用模型
                        preferred = [
                            m for m in available_models
                        ]
                        if preferred:
                            self.model = preferred[0]
                            await self.save_config()
                        
                except Exception as e:
                    logger.warning(f"API验证失败，使用默认配置: {str(e)}")
                    if not self.model:
                        self.model = settings.OPENAI_MODEL
            
        except Exception as e:
            logger.error(f"服务初始化失败: {str(e)}")
            raise
            
    async def ensure_analysis_ready(self):
        """确保分析所需的组件已初始化"""
        if not self.vector_store:
            self.vector_store = CodeVectorStore(
                persist_directory=paths.vector_store_dir
            )
        
        if not self.core_analyzer:
            self.core_analyzer = CoreAnalyzer()
            
    async def save_config(self):
        """保存API配置"""
        config = {
            "api_key": self.openai_api_key,
            "api_base": self.api_base,
            "model": self.model
        }
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(config, f)
            
    async def load_config(self):
        """加载保存的API配置"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                self.openai_api_key = config.get("api_key")
                self.api_base = config.get("api_base")
                self.model = config.get("model")
                logger.info(f"已加载保存的配置，使用模型: {self.model}")
        except Exception as e:
            logger.error(f"加载配置失败: {str(e)}")
        
    def _normalize_base_url(self, api_base: Optional[str]) -> Optional[str]:
        if not api_base:
            return api_base
        try:
            parsed = urlparse(api_base)
            host = parsed.netloc or parsed.path  # 支持传入裸域名
            base = api_base.rstrip('/')
            # Z.AI（OpenAI 兼容，路径 /api/paas/v4）
            if 'z.ai' in host and '/api/paas/' not in base:
                return f"{base}/api/paas/v4/"
            # SiliconFlow（OpenAI 兼容 /v1）
            if ('siliconflow' in host) and not base.endswith('/v1'):
                return f"{base}/v1"
            # Moonshot / OpenAI（/v1）
            if ('openai.' in host or 'moonshot' in host or 'api.moonshot' in host) and not base.endswith('/v1'):
                return f"{base}/v1"
            return api_base
        except Exception:
            return api_base

    def _apply_runtime_openai_config(self, api_key: Optional[str], api_base: Optional[str], model: Optional[str] = None):
        """根据请求覆盖当前的 OpenAI 配置"""
        if api_key:
            self._runtime_api_key = api_key
        if api_base:
            self._runtime_api_base = self._normalize_base_url(api_base)
        if model:
            self._runtime_model = model

    def _clear_runtime_openai_config(self):
        self._runtime_api_key = None
        self._runtime_api_base = None
        self._runtime_model = None

    def _resolve_openai_config(self) -> Dict[str, Optional[str]]:
        """聚合当前可用的 OpenAI 配置"""
        api_key = self._runtime_api_key or self.openai_api_key or settings.OPENAI_API_KEY
        api_base = self._runtime_api_base or self.api_base or settings.OPENAI_API_BASE
        api_base = self._normalize_base_url(api_base)
        model = self._runtime_model or self.model or settings.OPENAI_MODEL
        return {
            "api_key": api_key,
            "api_base": api_base,
            "model": model
        }

    async def configure_openai(self, api_key: str, api_base: str = None, model: str = None):
        """配置OpenAI API设置"""
        try:
            self.openai_api_key = api_key
            # 规范化 API 基础 URL
            if api_base:
                self.api_base = self._normalize_base_url(api_base)
            
            # 验证配置
            client = AsyncOpenAI(
                api_key=self.openai_api_key,
                base_url=self.api_base
            )
            
            try:
                # 获取可用模型列表
                models_response = await client.models.list()
                available_models = [m.id for m in models_response.data]
                logger.info(f"API配置成功，可用模型: {available_models}")
                
                # 如果指定了模型，验证是否可用
                if model:
                    model_variants = [model, model.replace("01-ai/", ""), f"01-ai/{model}"]
                    for variant in model_variants:
                        if variant in available_models:
                            self.model = variant
                            logger.info(f"使用指定模型: {self.model}")
                            break
                    else:
                        logger.warning(f"选择的模型 {model} 不在可用模型列表中")
                        self.model = available_models[0] if available_models else model
                else:
                    self.model = available_models[0] if available_models else self.model
                    
                logger.info(f"最终使用模型: {self.model}")
                
                # 保存配置
                await self.save_config()
                    
            except Exception as e:
                logger.error(f"API配置验证失败: {str(e)}")
                raise ValueError(f"API配置无效: {str(e)}")
            
        except Exception as e:
            logger.error(f"配置 OpenAI API 失败: {str(e)}")
            raise

    async def analyze_project(self, project_path: str, api_key: Optional[str] = None, api_base: Optional[str] = None, model: Optional[str] = None) -> Dict[str, Any]:
        """分析整个项目"""
        try:
            # 按需覆盖运行时配置
            self._apply_runtime_openai_config(api_key, api_base, model)

            # 1. 初始化分析器和向量数据库
            await self.ensure_initialized()
            await self.ensure_analysis_ready()
            
            # 2. 预处理：检查项目类型和文件有效性
            project_type = self._detect_project_type(project_path)
            logger.info(f"检测到项目类型: {project_type}")
            
            # 3. 本地静态扫描
            logger.info("开始静态扫描...")
            # 直接传递项目路径，而不是文件列表
            suspicious_files = await self.core_analyzer._static_scan(project_path)
            
            if not suspicious_files:
                logger.info("未发现可疑代码")
                return {
                    "status": "success",
                    "message": "未发现可疑代码",
                    "suspicious_files": [],
                    "ai_verification": {},
                    "summary": {
                        "total_files": len(self._get_valid_files(project_path, project_type)),
                        "total_issues": 0,
                        "risk_level": "low"
                    },
                    "recommendations": []
                }
            
            # 4. 导入向量数据库
            logger.info("导入向量数据库...")
            try:
                await self.core_analyzer._import_to_vector_store(project_path)
            except Exception as e:
                logger.error(f"导入向量数据库失败: {str(e)}")
                # 继续执行，不中断流程
            
            # 5. AI 深度分析
            logger.info("开始AI验证...")
            try:
                resolved_config = self._resolve_openai_config()
                results = await self.core_analyzer._ai_verify_suspicious(suspicious_files, resolved_config)
            except Exception as e:
                logger.error(f"AI验证失败: {str(e)}")
                results = {}
            finally:
                self._clear_runtime_openai_config()
            
            # 6. 生成最终报告
            return {
                "status": "success",
                "message": "分析完成",
                "project_type": project_type,
                "suspicious_files": suspicious_files,
                "ai_verification": results,
                "summary": {
                    "total_files": len(self._get_valid_files(project_path, project_type)),
                    "suspicious_files": len(suspicious_files),
                    "total_issues": sum(len(file.get("issues", [])) for file in suspicious_files),
                    "risk_level": self._calculate_risk_level(suspicious_files)
                },
                "recommendations": self._generate_recommendations(suspicious_files, results)
            }
            
        except Exception as e:
            logger.error(f"项目分析失败: {str(e)}")
            return {
                "status": "error",
                "message": str(e),
                "project_type": "unknown",
                "suspicious_files": [],
                "ai_verification": {},
                "summary": {
                    "total_files": 0,
                    "suspicious_files": 0,
                    "total_issues": 0,
                    "risk_level": "unknown"
                },
                "recommendations": []
            }

    def _detect_project_type(self, project_path: str) -> str:
        """检测项目类型"""
        try:
            project_path = Path(project_path)
            
            # 检查特征文件
            indicators = {
                'php': ['composer.json', 'index.php', '.php'],
                'python': ['requirements.txt', 'setup.py', '.py'],
                'javascript': ['package.json', '.js', '.ts'],
                'java': ['pom.xml', 'build.gradle', '.java']
            }
            
            # 统计各类型文件数量
            type_counts = {k: 0 for k in indicators.keys()}
            
            # 遍历项目文件
            for file_path in project_path.rglob('*'):
                if file_path.is_file():
                    # 检查特征文件
                    file_name = file_path.name.lower()
                    file_ext = file_path.suffix.lower()
                    
                    for lang, patterns in indicators.items():
                        if any(pattern in file_name or pattern == file_ext for pattern in patterns):
                            type_counts[lang] += 1
            
            # 根据文件数量判断项目类型
            if any(type_counts.values()):
                project_type = max(type_counts.items(), key=lambda x: x[1])[0]
                logger.info(f"检测到项目类型: {project_type}")
                return project_type
            
            return "unknown"
            
        except Exception as e:
            logger.error(f"项目类型检测失败: {str(e)}")
            return "unknown"

    def _get_valid_files(self, project_path: str, project_type: str) -> List[str]:
        """获取指定项目类型的有效文件"""
        try:
            project_path = Path(project_path)
            valid_files = []
            
            # 定义项目类型对应的文件扩展名
            type_extensions = {
                'php': ['.php'],
                'python': ['.py', '.pyw'],
                'javascript': ['.js', '.jsx', '.ts', '.tsx'],
                'java': ['.java', '.jsp']
            }
            
            # 获取当前项目类型支持的扩展名
            valid_extensions = type_extensions.get(project_type, [])
            if project_type == "auto":
                valid_extensions = [ext for exts in type_extensions.values() for ext in exts]
            
            # 忽略的目录
            ignore_dirs = {
                'node_modules', 'venv', '.git', '.svn', '__pycache__',
                'vendor', 'dist', 'build', 'target', 'tests', 'test'
            }
            
            # 遍历项目文件
            for file_path in project_path.rglob('*'):
                try:
                    # 检查是否在忽略目录中
                    if any(ignore_dir in file_path.parts for ignore_dir in ignore_dirs):
                        continue
                    
                    # 检查是否为文件
                    if not file_path.is_file():
                        continue
                    
                    # 检查是否为隐藏文件
                    if file_path.name.startswith('.'):
                        continue
                    
                    # 检查扩展名
                    if file_path.suffix.lower() in valid_extensions:
                        # 检查文件是否可读
                        try:
                            with open(file_path, 'r', encoding='utf-8'):
                                pass
                            valid_files.append(str(file_path))
                        except (UnicodeDecodeError, PermissionError):
                            continue
                        
                except Exception as e:
                    logger.error(f"处理文件失败 {file_path}: {str(e)}")
                    continue
                
            logger.info(f"找到 {len(valid_files)} 个有效的源代码文件")
            return valid_files
            
        except Exception as e:
            logger.error(f"获取有效文件失败: {str(e)}")
            return []

    async def _import_suspicious_to_vector_store(self, suspicious_files: List[Dict[str, Any]]):
        """仅导入可疑文件及其相关文件到向量数据库"""
        try:
            code_snippets = []
            for file_info in suspicious_files:
                file_path = Path(file_info["file_path"])  # 转换为 Path 对象
                
                # 获取文件内容，尝试不同的编码
                content = None
                encodings = ['utf-8', 'gbk', 'latin1']
                for encoding in encodings:
                    try:
                        with open(file_path, "r", encoding=encoding) as f:
                            content = f.read()
                        break
                    except UnicodeDecodeError:
                        continue
                        
                if content is None:
                    logger.warning(f"无法读取文件 {file_path}，跳过")
                    continue
                
                # 添加可疑文件
                code_snippets.append({
                    "code": content,
                    "file_path": str(file_path),  # 转换回字符串
                    "line_start": 1,
                    "line_end": len(content.splitlines()),
                    "metadata": {
                        "type": "suspicious",
                        "issues_json": json.dumps(file_info.get("issues", [])),
                        "language": file_info.get("language", "unknown")
                    }
                })
                
                # 获取相关文件
                related_files = self._get_related_files(str(file_path))  # 传入字符串
                for related_file in related_files:
                    related_path = Path(related_file)
                    if related_path != file_path:
                        # 尝试不同的编码读取相关文件
                        related_content = None
                        for encoding in encodings:
                            try:
                                with open(related_path, "r", encoding=encoding) as f:
                                    related_content = f.read()
                                break
                            except UnicodeDecodeError:
                                continue
                                
                        if related_content is None:
                            logger.warning(f"无法读取相关文件 {related_path}，跳过")
                            continue
                            
                        code_snippets.append({
                            "code": related_content,
                            "file_path": str(related_path),  # 转换回字符串
                            "line_start": 1,
                            "line_end": len(related_content.splitlines()),
                            "metadata": {
                                "type": "related",
                                "related_to": str(file_path),  # 转换回字符串
                                "language": self._check_file_type(str(related_path))
                            }
                        })
            
            # 批量导入向量数据库
            if code_snippets:
                await self.vector_store.add_code_to_store(code_snippets)
            
        except Exception as e:
            logger.error(f"导入向量数据库失败: {str(e)}")
            raise
        
    def _generate_empty_report(self) -> Dict[str, Any]:
        """生成空的分析报告"""
        return {
            "summary": {
                "total_files": 0,
                "total_issues": 0,
                "risk_level": "low",
                "scan_time": None,
                "project_info": {
                    "name": None,
                    "path": None,
                    "files_scanned": 0
                }
            },
            "details": {
                "suspicious_files": [],
                "ai_verification": {},
                "scan_coverage": {
                    "total_files": 0,
                    "scanned_files": 0,
                    "coverage_rate": 0
                }
            },
            "recommendations": []
        }
        
    def _generate_report(self, suspicious_files: List[Dict[str, Any]], ai_results: Dict[str, Any]) -> Dict[str, Any]:
        """生成分析报告"""
        try:
            total_files = len(suspicious_files)
            total_issues = sum(len(file_info.get("issues", [])) for file_info in suspicious_files)
            
            return {
                "summary": {
                    "total_files": total_files,
                    "total_issues": total_issues,
                    "risk_level": self._calculate_risk_level(suspicious_files),
                    "scan_time": None,  # TODO: 添加扫描时间
                    "project_info": {
                        "name": None,  # TODO: 添加项目名称
                        "path": None,  # TODO: 添加项目路径
                        "files_scanned": total_files
                    }
                },
                "details": {
                    "suspicious_files": [
                        {
                            "file_path": file_info["file_path"],
                            "language": file_info.get("language", "unknown"),
                            "issues": file_info.get("issues", []),
                            "ai_analysis": ai_results.get(file_info["file_path"], {})
                        }
                        for file_info in suspicious_files
                    ],
                    "scan_coverage": {
                        "total_files": total_files,
                        "scanned_files": total_files,
                        "coverage_rate": 100 if total_files > 0 else 0
                    }
                },
                "recommendations": self._generate_recommendations(suspicious_files, ai_results)
            }
        except Exception as e:
            logger.error(f"生成报告失败: {str(e)}")
            return self._generate_empty_report()
        
    def _calculate_risk_level(self, suspicious_files: List[Dict]) -> str:
        """计算整体风险等级"""
        try:
            high_count = 0
            medium_count = 0
            low_count = 0
            
            for file in suspicious_files:
                for issue in file.get("issues", []):
                    severity = issue.get("severity", "").lower()
                    if severity == "high":
                        high_count += 1
                    elif severity == "medium":
                        medium_count += 1
                    elif severity == "low":
                        low_count += 1
            
            if high_count > 0:
                return "high"
            elif medium_count > 0:
                return "medium"
            elif low_count > 0:
                return "low"
            else:
                return "info"
            
        except Exception:
            return "unknown"
        
    def _generate_recommendations(self, suspicious_files: List[Dict], ai_results: Dict) -> List[Dict]:
        """生成修复建议"""
        recommendations = []
        try:
            for file in suspicious_files:
                file_path = file.get("file_path", "")
                ai_result = ai_results.get(file_path, {})
                analysis = (ai_result.get("ai_analysis") or {}).get("analysis") or {}
                recs = analysis.get("recommendations", [])
                for rec in recs:
                    if isinstance(rec, dict):
                        recommendations.append({
                            "file": file_path,
                            "issue": rec.get("issue", ""),
                            "solution": rec.get("solution", "")
                        })
            
        except Exception as e:
            logger.error(f"生成修复建议失败: {str(e)}")
        
        return recommendations

    def _get_related_files(self, file_path: str) -> List[str]:
        """获取与指定文件相关的文件"""
        try:
            related_files = []
            file_path = Path(file_path)  # 转换为 Path 对象
            file_dir = file_path.parent
            
            # 1. 检查同目录下的文件
            for f in file_dir.iterdir():
                if f.is_file() and f != file_path:
                    related_files.append(str(f))  # 转换为字符串
            
            # 2. 检查包含关系
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # 检查 PHP 的 include/require
            if file_path.suffix.lower() == '.php':
                includes = re.findall(r'(?:include|require)(?:_once)?\s*[\'"]([^\'"]+)[\'"]', content)
                for inc in includes:
                    inc_path = file_dir / inc  # 使用 Path 对象的 / 运算符
                    if inc_path.exists():
                        related_files.append(str(inc_path))
            
            # 检查 Python 的 import
            elif file_path.suffix.lower() == '.py':
                imports = re.findall(r'(?:from|import)\s+([\w.]+)', content)
                for imp in imports:
                    imp_parts = imp.split('.')
                    imp_path = file_dir.joinpath(*imp_parts).with_suffix('.py')
                    if imp_path.exists():
                        related_files.append(str(imp_path))
            
            # 检查 JavaScript 的 require/import
            elif file_path.suffix.lower() in ('.js', '.jsx', '.ts', '.tsx'):
                imports = re.findall(r'(?:require|import)\s*[\(\{]\s*[\'"]([^\'"]+)[\'"]', content)
                for imp in imports:
                    imp_path = file_dir / imp  # 基本路径
                    # 检查多个可能的扩展名
                    possible_exts = ['.js', '.jsx', '.ts', '.tsx']
                    for ext in possible_exts:
                        full_path = imp_path.with_suffix(ext)
                        if full_path.exists():
                            related_files.append(str(full_path))
                            break
            
            return list(set(related_files))  # 去重
            
        except Exception as e:
            logger.error(f"获取相关文件失败 {file_path}: {str(e)}")
            return []

    def _check_file_type(self, file_path: str) -> str:
        """检查文件类型"""
        ext = Path(file_path).suffix.lower()  # 使用 Path 对象获取扩展名
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'react',
            '.tsx': 'react',
            '.php': 'php',
            '.java': 'java',
            '.cs': 'csharp',
            '.go': 'go',
            '.rb': 'ruby',
            '.html': 'html',
            '.css': 'css',
            '.sql': 'sql'
        }
        return language_map.get(ext, 'unknown')

    async def analyze_code(self, code: str, language: str, api_key: str = None, api_base: str = None, file_name: str = "uploaded_file", model: Optional[str] = None) -> Dict[str, Any]:
        """分析单个代码文件"""
        try:
            self._apply_runtime_openai_config(api_key, api_base, model)
            # 初始化
            await self.ensure_initialized()
            await self.ensure_analysis_ready()
            
            # 进行代码分析
            faux_path = file_name if file_name else f"temp.{language}" if language else "temp.unknown"
            issues = self.core_analyzer._check_suspicious(code, faux_path)

            # 尝试额外的动态检测（例如常见ORM执行函数）
            if language == 'python' and not issues:
                orm_sinks = ['Session.execute', 'cursor.execute', 'raw', 'executesql']
                for sink in orm_sinks:
                    if sink in code:
                        issues.append({
                            "type": "sql_injection",
                            "line": 0,
                            "description": f"检测到潜在的数据库执行调用: {sink}",
                            "severity": "medium"
                        })
                        break
 
            if not issues:
                empty_report = self._generate_empty_report()
                return {
                    "status": "success",
                    "message": "未发现可疑代码",
                    "issues": [],
                    "report": empty_report,
                    "summary": empty_report["summary"],
                    "details": empty_report["details"],
                    "recommendations": empty_report["recommendations"]
                }
            
            # 生成报告
            report = self._generate_report([{
                "file_path": faux_path,
                "issues": issues,
                "language": language
            }], {})
            
            return {
                "status": "success",
                "issues": issues,
                "report": report,
                "summary": report["summary"],
                "details": report["details"],
                "recommendations": report["recommendations"]
            }
        
        except Exception as e:
            logger.error(f"代码分析失败: {str(e)}")
            empty_report = self._generate_empty_report()
            return {
                "status": "error",
                "message": str(e),
                "issues": [],
                "report": empty_report,
                "summary": empty_report["summary"],
                "details": empty_report["details"],
                "recommendations": empty_report["recommendations"]
            }
        finally:
            self._clear_runtime_openai_config()

    def scan_project(self, project_path: str) -> List[str]:
        """扫描项目文件"""
        valid_files = []
        try:
            # 添加调试日志
            logger.debug(f"开始扫描项目: {project_path}")
            
            for root, _, files in os.walk(project_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # 添加调试日志
                    logger.debug(f"检查文件: {file_path}")
                    if file_path.endswith(('.php', '.blade.php', '.js', '.ts', '.tsx', '.py', '.java', '.jsp', '.jspx')):
                        valid_files.append(file_path)
                        logger.debug(f"添加有效文件: {file_path}")
                        
            logger.info(f"找到 {len(valid_files)} 个有效的源代码文件")
            return valid_files
            
        except Exception as e:
            logger.error(f"扫描项目失败: {str(e)}")
            return [] 