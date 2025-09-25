from typing import List, Dict, Any
import numpy as np
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
import logging
import asyncio
from backend.config import settings, paths
import json

logger = logging.getLogger(__name__)

class CodeVectorStore:
    def __init__(self, persist_directory: str = "vector_store"):
        """初始化向量数据库"""
        self.embeddings = HuggingFaceEmbeddings(
            model_name="all-MiniLM-L6-v2"
        )
        self.vector_store = Chroma(
            persist_directory=str(persist_directory),
            embedding_function=self.embeddings,
            collection_name="code_snippets"
        )
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=settings.VECTOR_CHUNK_SIZE,
            chunk_overlap=settings.VECTOR_CHUNK_OVERLAP
        )
        
    def _prepare_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """准备元数据，将复杂类型转换为字符串"""
        processed = {}
        for key, value in metadata.items():
            if isinstance(value, (str, int, float, bool)):
                processed[key] = value
            else:
                # 将复杂类型转换为 JSON 字符串
                processed[key] = json.dumps(value)
        return processed
        
    async def add_code_to_store(self, code_snippets: List[Dict[str, Any]]):
        """添加代码到向量数据库"""
        try:
            texts = []
            metadatas = []
            
            for snippet in code_snippets:
                texts.append(snippet["code"])
                metadata = {
                    "file_path": snippet["file_path"],
                    "line_start": snippet["line_start"],
                    "line_end": snippet["line_end"]
                }
                
                if "metadata" in snippet:
                    extra_metadata = self._prepare_metadata(snippet["metadata"])
                    metadata.update(extra_metadata)
                    
                metadatas.append(metadata)
            
            # 使用 asyncio.to_thread 包装同步操作
            await asyncio.to_thread(
                self.vector_store.add_texts,
                texts=texts,
                metadatas=metadatas
            )
            
        except Exception as e:
            logger.error(f"Error adding code to vector store: {str(e)}")
            raise

    async def search_similar_code(self, query: str, n_results: int = 5, threshold: float = 0.8) -> List[Dict[str, Any]]:
        """搜索相似代码片段，增加相似度阈值过滤"""
        try:
            # 使用 asyncio.to_thread 包装同步操作
            results = await asyncio.to_thread(
                self.vector_store.similarity_search_with_score,
                query,
                k=n_results * 2  # 获取更多结果用于过滤
            )
            
            # 过滤低相似度结果
            filtered_results = [
                {
                    "code": doc.page_content,
                    "metadata": doc.metadata,
                    "similarity": score
                }
                for doc, score in results
                if score >= threshold
            ]
            
            # 返回前n_results个结果
            return filtered_results[:n_results]
            
        except Exception as e:
            logger.error(f"Error searching vector store: {str(e)}")
            raise 