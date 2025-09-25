import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from openai import AsyncOpenAI
from typing import List, Optional, Dict, Set
import os
import logging
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from enum import Enum
from urllib.parse import urlparse
import zipfile
import tarfile
from core.analyzers import CoreAnalyzer
from .config import settings, paths
from .services import CodeAuditService

# 只保留 ModelType 枚举，但不作为默认配置
class ModelType(str, Enum):
    GPT35 = "gpt-3.5-turbo"
    GPT4 = "gpt-4"
    CLAUDE = "claude-2"
    CLAUDE3 = "claude-3"

# 配置日志
logging.basicConfig(
    level=getattr(logging, str(settings.LOG_LEVEL)),
    format=settings.LOG_FORMAT,
    handlers=[
        logging.FileHandler(str(paths.log_file)),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Mirror-Flowers")

# 添加 CORS 支持
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 修改静态文件路径
static_path = Path(__file__).parent / "static"
if not static_path.exists():
    static_path.mkdir(parents=True)

# 挂载静态文件
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# 确保上传目录存在
os.makedirs(str(paths.upload_dir), exist_ok=True)

# 添加新的数据模型
class ProjectAuditResult(BaseModel):
    file_path: str
    language: str
    vulnerabilities: List[dict]
    related_files: List[str]
    context_analysis: str

class ProjectAnalysis:
    def __init__(self):
        self.file_dependencies: Dict[str, Set[str]] = {}  # 文件依赖关系
        self.shared_variables: Dict[str, Set[str]] = {}   # 共享变量
        self.function_calls: Dict[str, Set[str]] = {}     # 函数调用关系
        self.vulnerability_context: Dict[str, List[dict]] = {}  # 漏洞上下文

    def add_dependency(self, file: str, depends_on: str):
        if file not in self.file_dependencies:
            self.file_dependencies[file] = set()
        self.file_dependencies[file].add(depends_on)

    def add_shared_variable(self, file: str, variable: str):
        if file not in self.shared_variables:
            self.shared_variables[file] = set()
        self.shared_variables[file].add(variable)

    def add_function_call(self, source_file: str, target_file: str):
        if source_file not in self.function_calls:
            self.function_calls[source_file] = set()
        self.function_calls[source_file].add(target_file)

    def get_related_files(self, file: str) -> Set[str]:
        """获取与指定文件相关的所有文件"""
        related = set()
        if file in self.file_dependencies:
            related.update(self.file_dependencies[file])
        if file in self.function_calls:
            related.update(self.function_calls[file])
        return related

# 依赖注入函数
async def get_audit_service() -> CodeAuditService:
    """获取代码审计服务实例"""
    try:
        service = CodeAuditService()
        await service.ensure_initialized()  # 只调用 ensure_initialized
        return service
    except Exception as e:
        logger.error(f"获取审计服务失败: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"服务初始化失败: {str(e)}"
        )

# 添加请求体模型
class ConfigureRequest(BaseModel):
    api_key: str
    api_base: Optional[str] = None
    model: Optional[str] = None  # 添加模型选择

# 修改获取可用模型的API
@app.get("/api/models")
async def get_available_models(
    audit_service: CodeAuditService = Depends(get_audit_service)
):
    """获取当前API地址支持的模型列表"""
    try:
        # 如果没有 API 配置，先尝试加载保存的配置
        if not audit_service.api_base:
            await audit_service.load_config()
        
        api_base = audit_service.api_base or settings.OPENAI_API_BASE
        api_key = audit_service.openai_api_key or settings.OPENAI_API_KEY
        
        api_base = audit_service._normalize_base_url(api_base)
        
        # 创建 OpenAI 客户端
        client = AsyncOpenAI(
            api_key=api_key,
            base_url=api_base
        )
        
        try:
            models_response = await client.models.list()
            available_models = [m.id for m in models_response.data]
            
            models_by_type = {
                "Chat": [],
                "Image": [],
                "Audio": [],
                "Embedding": []
            }
            
            for model_id in available_models:
                lower_id = model_id.lower()
                # 常见 Chat 模型
                if any(x in lower_id for x in [
                    'gpt', 'claude', 'qwen', 'glm', 'deepseek', 'kimi', 'moonshot', 'sonnet', 'haiku', 'opus'
                ]):
                    models_by_type["Chat"].append(model_id)
                elif 'embedding' in lower_id:
                    models_by_type["Embedding"].append(model_id)
                else:
                    models_by_type["Chat"].append(model_id)
            
            current_model = audit_service.model or (models_by_type["Chat"][0] if models_by_type["Chat"] else None)
            if current_model:
                audit_service.model = current_model
                await audit_service.save_config()
            
            logger.info(f"当前API地址: {api_base}")
            logger.info(f"可用模型: {models_by_type}")
            logger.info(f"当前使用的模型: {current_model}")
            
            return {
                "models": models_by_type,
                "current_model": current_model
            }
            
        except Exception as e:
            logger.error(f"从API获取模型列表失败: {str(e)}")
            # 基于已知提供商提供默认列表
            domain = urlparse(api_base).netloc
            if 'z.ai' in domain:
                default_models = {"Chat": ["glm-4.5", "glm-4.5v"], "Embedding": []}
            elif 'siliconflow' in domain:
                default_models = {"Chat": [
                    "deepseek-ai/DeepSeek-R1",
                    "deepseek-ai/DeepSeek-V3.1",
                    "moonshotai/Kimi-K2-Instruct",
                    "moonshotai/Kimi-K2-Instruct-0905",
                    "zai-org/GLM-4.5",
                    "zai-org/GLM-4.5-Air"
                ]}
            else:
                default_models = {
                    "Chat": [
                        "gpt-4.1", "gpt-4o", "claude-3.5-sonnet", "gemini-1.5-pro"
                    ],
                    "Embedding": []
                }
            current_model = audit_service.model or (default_models["Chat"][0] if default_models["Chat"] else None)
            return {"models": default_models, "current_model": current_model}
            
    except Exception as e:
        logger.error(f"获取模型列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# 修改配置路由
@app.post("/api/configure")
async def configure_api(
    config: ConfigureRequest,
    audit_service: CodeAuditService = Depends(get_audit_service)
):
    """配置OpenAI API设置"""
    try:
        await audit_service.configure_openai(
            config.api_key, 
            config.api_base,
            config.model
        )
        return {
            "status": "success", 
            "message": "API配置已更新",
            "model": audit_service.model
        }
    except Exception as e:
        logger.error(f"配置更新失败: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/audit")
async def audit_code(
    file: UploadFile = File(...),
    api_key: str = Form(None),
    api_base: str = Form(None),
    audit_service: CodeAuditService = Depends(get_audit_service)
):
    """审计代码，支持自定义API设置"""
    try:
        content = await file.read()
        code = content.decode()
        
        # 获取文件扩展名并检查支持的类型
        language = audit_service._check_file_type(file.filename)
        
        logger.info(f"开始分析{file.filename}")
        
        result = await audit_service.analyze_code(
            code,
            language,
            api_key=api_key,
            api_base=api_base,
            file_name=file.filename
        )
        return result
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="文件编码错误")
    except Exception as e:
        logger.error(f"处理文件时发生错误: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/audit/project")
async def audit_project(
    project: UploadFile = File(...),
    api_key: str = Form(None),
    api_base: str = Form(None),
    audit_service: CodeAuditService = Depends(get_audit_service)
):
    """审计整个项目代码"""
    try:
        # 保存上传的项目文件
        project_path = await save_project_file(project)
        
        # 执行项目分析
        results = await audit_service.analyze_project(project_path)
        
        # 直接返回分析结果，不要再包装一层
        return {
            **results,  # 展开 results 对象
            "project_path": project_path
        }
        
    except Exception as e:
        logger.error(f"项目审计失败: {str(e)}")
        # 发生错误时返回一个完整的错误响应
        empty_report = audit_service._generate_empty_report()
        return {
            "status": "error",
            "message": str(e),
            "suspicious_files": [],
            "ai_verification": {},
            "report": empty_report,
            "summary": empty_report["summary"],
            "details": empty_report["details"],
            "recommendations": empty_report["recommendations"],
            "project_path": project_path if 'project_path' in locals() else None
        }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/")
async def root():
    """
    根路径处理程序，返回API基本信息
    """
    return {
        "name": "Mirror-Flowers",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "audit": "/api/audit",
            "configure": "/api/configure",
            "health": "/health",
            "docs": "/docs"
        }
    }

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """
    全局异常处理
    """
    error_msg = str(exc)
    logger.error(f"发生错误: {error_msg}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "内部服务器错误",
            "detail": error_msg
        }
    )

@app.middleware("http")
async def log_requests(request, call_next):
    """
    请求日志中间件
    """
    logger.info(f"收到请求: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"响应状态码: {response.status_code}")
    return response

async def save_project_file(project: UploadFile) -> str:
    """保存上传的项目文件"""
    try:
        temp_dir = os.path.join(str(paths.upload_dir), f"project_{os.urandom(8).hex()}")
        os.makedirs(temp_dir, exist_ok=True)
        
        file_path = os.path.join(temp_dir, project.filename)
        with open(file_path, "wb") as f:
            content = await project.read()
            f.write(content)
            
        # 如果是压缩文件，解压
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            os.remove(file_path)
        elif file_path.endswith(('.tar.gz', '.tgz')):
            with tarfile.open(file_path, 'r:gz') as tar_ref:
                tar_ref.extractall(temp_dir)
            os.remove(file_path)
            
        return temp_dir
        
    except Exception as e:
        logger.error(f"保存项目文件失败: {str(e)}")
        raise 

@app.get("/ui")
async def serve_spa():
    """
    服务前端单页应用
    """
    return FileResponse(str(static_path / "index.html")) 