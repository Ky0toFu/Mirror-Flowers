from pydantic_settings import BaseSettings
from typing import Dict, List
import os
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class Settings(BaseSettings):
    # API配置
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_API_BASE: str = os.getenv("OPENAI_API_BASE", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "")
    
    # 日志配置
    LOG_LEVEL: LogLevel = os.getenv("LOG_LEVEL", LogLevel.INFO)
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # 向量数据库配置
    VECTOR_MODEL: str = "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B" #deepseek-ai/DeepSeek-R1-Distill-Qwen-7B  #all-MiniLM-L6-v2
    VECTOR_CHUNK_SIZE: int = 500
    VECTOR_CHUNK_OVERLAP: int = 100
    
    # 支持的文件类型
    SUPPORTED_LANGUAGES: Dict[str, str] = {
        '.php': 'php',
        '.java': 'java',
        '.py': 'python',
        '.js': 'javascript'
    }
    
    # 服务器配置
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # CORS 配置
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",     # React 开发服务器
        "http://127.0.0.1:3000",
        "http://localhost:8000",     # FastAPI 服务器
        "http://127.0.0.1:8000",
    ]
    
    def get_default_models(self, api_base: str) -> Dict[str, List[str]]:
        """根据API地址返回默认支持的模型列表"""
        domain = urlparse(api_base).netloc
        logger.info(f"部分匹配到域名: {domain}")
        
        if "siliconflow" in domain:
            return {
                "Chat": [
                    "01-ai/Yi-1.5-34B-Chat-16K",
                    "01-ai/Yi-1.5-6B-Chat",
                    "01-ai/Yi-1.5-9B-Chat-16K",
                    "THUDM/chatglm3-6b",
                    "THUDM/glm-4-9b-chat"
                ],
                "Embedding": [
                    "BAAI/bge-large-zh-v1.5",
                    "BAAI/bge-large-en-v1.5"
                ]
            }
        else:
            return {
                "Chat": ["01-ai/Yi-1.5-34B-Chat-16K"],
                "Embedding": ["BAAI/bge-large-zh-v1.5"]
            }

    class Config:
        env_file = ".env"
        extra = "allow"
        use_enum_values = True

class PathSettings:
    def __init__(self, settings: Settings):
        self._project_root = Path(__file__).parent.parent
        
        # 创建必要的目录
        self.upload_dir = self._ensure_dir("uploads")
        self.vector_store_dir = self._ensure_dir("vector_store")
        self.log_dir = self._ensure_dir("logs")
        self.config_dir = self._ensure_dir("config")  # 添加配置目录
        self.log_file = self.log_dir / "app.log"
        
    def _ensure_dir(self, name: str) -> Path:
        path = self._project_root / name
        path.mkdir(parents=True, exist_ok=True)
        return path

# 创建全局配置实例
settings = Settings()
paths = PathSettings(settings)

# 确保所有必要的目录存在
for directory in [paths.upload_dir, paths.log_dir, paths.vector_store_dir]:
    os.makedirs(directory, exist_ok=True) 