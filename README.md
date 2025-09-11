# 基于AI大模型代码审计系统 - AI 驱动的代码安全审计工具

基于AI大模型代码审计系统 是一个基于 AI 的代码安全审计工具，能够自动检测代码中的安全漏洞并提供详细的分析和修复建议。

## 特性

- 支持多种编程语言（PHP、Python、Java、JavaScript）
- 本地静态代码分析
- AI 驱动的漏洞验证和分析
- 详细的安全报告和修复建议
- 支持单文件和项目文件夹分析
- 深色/浅色主题切换
- 实时分析进度显示


## 更新记录
### 2025-02-17
- 修复了API配置保存和调用的问题
- 修复了AI分析结果在前端显示的问题
- 优化了JSON响应格式，确保前端能正确解析和显示AI分析建议


### 2025-02-14
- 优化了依赖管理：
  - 更新了 setup.py 配置
  - 重构了 requirements.txt
  - 添加了开发依赖选项
- 改进了前端显示：
  - 优化了 AI 分析建议的展示
  - 添加了更详细的漏洞分析信息
  - 改进了深色模式支持
- 文档更新：
  - 完善了安装说明
  - 添加了详细的使用说明
  - 更新了 API 配置说明
- 核心功能增强：
  - 实现了基于向量数据库的代码分析
  - 支持将所有源码导入本地向量库
  - 新增指定方法获取潜在漏洞入口点
  - 实现 AI 与向量库关联分析功能
  - 优化了代码上下文理解能力
  - 提高了漏洞分析的准确性

### 2025-02-11
- 完善了Python代码分析功能：
  - 添加了完整的依赖分析，支持追踪导入关系和别名
  - 增强了函数调用分析，支持类方法和实例方法的调用追踪
  - 添加了变量使用分析，支持追踪全局变量和实例变量
  - 改进了类继承分析，支持多级继承路径分析
- 优化了分析器架构：
  - 使用访问者模式重构了代码分析逻辑
  - 添加了类型提示和详细文档
  - 改进了错误处理机制

## 支持的API接口

FREEGPTAPI：https://github.com/popjane/free_chatgpt_api

SiliconFlow(硅基流动)：https://cloud.siliconflow.cn/i/JzMCyiJ3

如需要使用GPT大模型则使用FREEGPTAPI，使用DeepSeek-R1大模型则使用SiliconFlow API。

SiliconFlow(硅基流动)注册可免费领取14元使用额度，可通过SMS接码平台注册账号，理论可无限免费使用API KEY。

### API 配置说明

配置文件位置: `config/api_config.json`



```json

{

    "api_key": "your_api_key",

    "api_base": "your_api_base_url",

    "model": "your_preferred_model"

}

```


## 核心功能

### 多语言支持
- PHP
- Java
- Python
- JavaScript

### 依赖分析
- Maven (pom.xml)
- NPM (package.json)
- Python (requirements.txt)
- Composer (composer.json)

### 框架安全分析
- Spring Framework
  - Spring Security配置审计
  - 权限控制检查
  - CSRF/XSS防护
  - 跨域配置检查

- Django
  - 中间件配置检查
  - CSRF Token验证
  - XSS防护配置
  - 调试模式检查

- Express.js
  - 安全中间件配置
  - 认证机制检查
  - CORS配置审计
  - 输入验证检查

- Hibernate
  - HQL注入检测
  - 缓存配置审计
  - 实体验证检查
  - 会话管理检查

### 安全检查特性

#### PHP安全检查
- 文件包含漏洞（include/require）
- SQL注入（mysql_*函数）
- 命令注入（system, exec, shell_exec）
- 文件上传漏洞
- 反序列化漏洞（unserialize）
- XSS（echo, print）
- SSRF漏洞
- 目录遍历
- 会话管理问题
- 配置文件泄露

#### Java安全检查
- SQL注入（PreparedStatement相关）
- 命令注入（Runtime.exec, ProcessBuilder）
- XXE漏洞（XML解析器配置）
- 反序列化漏洞（readObject）
- 不安全的文件操作
- CSRF/XSS防护
- 权限控制缺陷
- 线程安全问题
- 密码学实现缺陷
- 日志信息泄露

#### Python安全检查
- 不安全的反序列化（pickle.loads, yaml.load）
- 命令注入（os.system, eval, exec, subprocess）
- 不安全的模块导入（__import__）
- SQL注入（字符串格式化, execute）
- 路径遍历（open, os.path）
- 模板注入（render_template_string）
- 密码学实现问题（weak random）
- 环境变量泄露
- 调试配置泄露
- 不安全的依赖加载

#### JavaScript安全检查
- XSS（DOM型和反射型）
- 原型污染
- 不安全的第三方依赖
- 客户端存储安全
- 不安全的随机数生成
- CSRF防护缺失
- 跨域配置问题
- 敏感信息泄露
- 不安全的正则表达式
- 事件监听器泄露

### 分析器组件
- TaintAnalyzer: 污点分析和数据流追踪
- SecurityAnalyzer: 通用安全问题检测
- DependencyAnalyzer: 依赖组件安全分析
- FrameworkAnalyzer: 框架特定安全检查
- ConfigAnalyzer: 配置文件安全分析
- ContextAnalyzer: 上下文感知分析

### 向量数据库分析
- 代码向量化：
  - 支持多种编程语言的代码向量化
  - 保留代码语义和结构信息
  - 高效的本地向量存储

- 漏洞入口分析：
  - 智能识别潜在漏洞入口点
  - 基于上下文的代码关联分析
  - 支持跨文件依赖追踪

- AI 关联分析：
  - 与向量库深度集成
  - 基于相似度的代码片段匹配
  - 智能关联漏洞模式识别
  - 上下文感知的安全建议

## 安装和配置

### 环境要求
- Python 3.8+
- FastAPI
- Node.js (前端开发)

### 快速开始

1. 克隆项目
```bash

```

2. 安装依赖（选择以下任一方式）

方法 1: 开发模式安装
```bash
pip install -e .
```

方法 2: 从 requirements.txt 安装
```bash
pip install -r requirements.txt
```

安装开发依赖（可选）
```bash
pip install -e ".[dev]"
```

3. 配置环境变量
```env
OPENAI_API_KEY=your_api_key_here
OPENAI_API_BASE=your_api_base_url
OPENAI_MODEL=your_preferred_model
```

4. 启动服务
```bash
uvicorn backend.app:app --reload
```

5. 访问Mirror-Flowers
```bash
http://localhost:8000/ui
```

## 访问
- Web 界面：http://127.0.0.1:8000/ui
- API 文档：http://127.0.0.1:8000/docs

## 使用方法

1. 访问 Web 界面
2. 配置更新 API
3. 选择分析模式（单文件/项目文件夹）
4. 上传代码文件
5. 等待分析完成
6. 查看分析结果和 AI 建议

## 支持的文件类型

- PHP: `.php`
- Python: `.py`, `.pyw`
- Java: `.java`, `.jsp`
- JavaScript: `.js`, `.jsx`, `.ts`, `.tsx`
- 辅助文件: `.html`, `.css`, `.json`, `.xml`, `.yml`, `.yaml`

## 贡献

欢迎提交 Pull Requests 和 Issues。

## 注意事项
1. API密钥安全：请妥善保管API密钥
2. 分析时间：大型项目可能需要较长时间
3. 结果验证：建议结合人工审查
4. API配置问题：如果提示"API配置更新错误"或"不存在某个模型"，请检查API Base URL格式，尝试在URL后添加/v1或删除/v1（例如：https://api.example.com 或 https://api.example.com/v1）


## 项目结构
```
Mirror-Flowers/
├── frontend/          # Vue.js前端
├── backend/           # Python FastAPI后端
│   ├── static/        # 静态资源文件
│   ├── services/      # 业务逻辑服务
│   └── config.py      # 配置文件
├── core/              # 核心审计逻辑
│   ├── analyzers/     # 各种分析器
│   ├── parsers/       # 代码解析器
│   └── ai/           # AI分析模块
└── docker/           # Docker配置文件
```

## 技术架构

### 后端组件
- FastAPI: Web框架
- ChromaDB: 向量数据库
- LangChain: AI链式调用
- OpenAI/DeepSeek: 大语言模型

### 前端技术
- Bootstrap 5.1.3
- Vue.js (可选)

### 核心功能实现
- 向量数据库集成
  - 使用 ChromaDB 存储代码向量
  - 支持语义相似度搜索
  - 实现代码上下文关联

- AI 分析流程
  - 静态代码扫描
  - 向量数据库导入
  - AI 验证分析
  - 漏洞关联分析
  - 修复建议生成

## 环境变量说明
```env
# 必需配置
OPENAI_API_KEY=your_api_key_here
OPENAI_API_BASE=your_api_base_url
OPENAI_MODEL=your_preferred_model

# 可选配置
LOG_LEVEL=INFO              # 日志级别：DEBUG/INFO/WARNING/ERROR
CORS_ORIGINS=["*"]          # CORS 配置
VECTOR_STORE_DIR=vector_db  # 向量数据库存储目录
UPLOAD_DIR=uploads          # 文件上传目录
LOG_DIR=logs               # 日志目录
```

## 开发指南

### 本地开发
1. 安装开发依赖
```bash
pip install -e ".[dev]"
```
mac系统直接执行下面操作安装sentence-transformers/all-MiniLM-L6-v2向量数据库
```aiignore
# 安装 ModelScope CLI
pip install modelscope

# 下载模型到本地目录
modelscope download --model 'sentence-transformers/all-MiniLM-L6-v2' --local_dir './models'

```
windows系统直接执行git clone https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2 

2. 代码格式化
```bash
black .
isort .
```

3. 类型检查
```bash
mypy .
```

4. 运行测试
```bash
pytest
```

### 目录说明
- `backend/static/`: 存放前端静态文件
- `core/analyzers/`: 核心分析器实现
- `core/parsers/`: 各语言解析器
- `core/ai/`: AI 模型集成

### API 文档
启动服务后访问：http://127.0.0.1:8000/docs


