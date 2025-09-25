# Mirror Flowers (镜花) · AI 代码安全审计工具

Mirror Flowers 是一个开箱即用的代码安全审计工具，集成本地静态扫描（行级污点追踪 + AST）与 AI 验证，帮助你快速发现并定位高风险问题，并给出修复建议。

## 核心能力
- 多语言：PHP / Python / JavaScript/TypeScript / Java
- 本地静态扫描：行级污点追踪 + AST 访问器，结果合并去重，误报更少
- AI 验证（可选）：调用 OpenAI 兼容接口，对命中的可疑点给出证据、影响与修复建议
- 单文件/项目两种模式：
  - 单文件：轻量、无需向量库加载
  - 项目：支持 `.zip/.tar.gz/.tgz` 上传，自动解压；可按需导入向量库做上下文辅助
- 并发加速：文件扫描、AI 验证都带并发与超时保护
- 一体化 UI：在 `/ui` 直接上传文件/项目即可得到可视化结果（按漏洞类型分组、AI 建议就地展示）
- 兼容多家 OpenAI 接口提供商：Z.AI / SiliconFlow / Moonshot（Kimi）等（自动规范化 base_url）

## 最新变更（2025-09-25）
- 检测精度：
  - PHP 新增行级污点追踪（支持变量先赋值再用于 include/require、SQL、文件操作等敏感点）
  - AST 与行级结果合并去重，降低漏报/误报
  - 项目扫描拓展到 `.java/.jsp/.jspx`
- AI 与前端：
  - `/api/audit`、`/api/audit/project` 支持通过 multipart 按请求覆盖 `api_key`/`api_base`
  - 修复建议路径规范化，前端稳定展示
- 兼容与性能：
  - 向量库改为惰性初始化（单文件审计不拉取嵌入模型）
  - 前端不再强制拼 `/v1`，由后端统一归一化 `api_base`

## 快速开始
### 依赖
- Python 3.9+
- 无需单独安装前端构建工具（内置静态页面）

### 安装
```bash
pip install -r requirements.txt
```

### 运行
开发模式：
```bash
uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```
访问 UI：`http://127.0.0.1:8000/ui`

## 配置模型提供商（OpenAI 兼容）
你可以通过环境变量或 API 配置。后端会自动规范化不同厂商的 base_url（兼容 Z.AI `/api/paas/v4`、SiliconFlow `/v1`、Moonshot/OpenAI `/v1`）。

方式 A · 环境变量（可选）
```env
OPENAI_API_KEY=your_key
OPENAI_API_BASE=https://api.siliconflow.cn
OPENAI_MODEL=moonshotai/Kimi-K2-Instruct-0905   # 或任意可用模型
```

方式 B · 通过接口配置（推荐）
```bash
# Z.AI（GLM-4.5 示例）
curl -X POST http://127.0.0.1:8000/api/configure \
  -H 'Content-Type: application/json' \
  -d '{"api_key":"YOUR_ZAI_API_KEY","api_base":"https://api.z.ai","model":"glm-4.5"}'

# SiliconFlow（DeepSeek/Kimi/GLM 示例）
curl -X POST http://127.0.0.1:8000/api/configure \
  -H 'Content-Type: application/json' \
  -d '{"api_key":"YOUR_SF_KEY","api_base":"https://api.siliconflow.cn","model":"deepseek-ai/DeepSeek-R1"}'

# Moonshot / Kimi（K2 示例）
curl -X POST http://127.0.0.1:8000/api/configure \
  -H 'Content-Type: application/json' \
  -d '{"api_key":"YOUR_MOONSHOT_KEY","api_base":"https://api.moonshot.cn","model":"moonshotai/Kimi-K2-Instruct-0905"}'
```
> 注：UI 中更新配置同样生效；你也可以在上传时以 multipart 字段临时覆盖 `api_key`/`api_base`。

## 使用方法
### 方式一：Web UI（推荐）
1. 打开 `http://127.0.0.1:8000/ui`
2. 在“API 配置”中填入 Key / Base / 模型（或使用已保存配置）
3. 选择“单文件审计”或“项目文件夹审计”并上传
4. 查看“审计摘要”“问题（按类型分组）”“AI 建议”

### 方式二：HTTP API
- 单文件审计
```bash
curl -X POST http://127.0.0.1:8000/api/audit \
  -F file=@/path/to/file.php \
  -F api_key=YOUR_KEY \
  -F api_base=https://api.siliconflow.cn
```
- 项目审计（支持 .zip/.tar.gz/.tgz）
```bash
curl -X POST http://127.0.0.1:8000/api/audit/project \
  -F project=@/path/to/project.zip \
  -F api_key=YOUR_KEY \
  -F api_base=https://api.siliconflow.cn
```

## 可调参数（环境变量）
- `SCAN_CONCURRENCY`（默认 6）：文件扫描并发度
- `AI_CONCURRENCY`（默认 3）：AI 验证并发度
- `AI_TIMEOUT_SEC`（默认 120）：单条 AI 验证超时
- `VECTOR_BATCH_SIZE`（默认 300）：向量导入批大小（项目模式）

## 主要能力与覆盖
- PHP：文件包含（include/require）、命令执行（system/exec 等）、SQL 注入（含拼接启发式）、XSS、上传风险、弱哈希（md5/sha1）、不安全反序列化、会话固定、参数污染（$_REQUEST）、IDOR 启发式
- Python：命令执行（os/subprocess/eval/exec）、SQL 注入（execute 拼接）、路径遍历、不安全反序列化（pickle/yaml）
- JS/TS：危险函数（eval/Function/document.write 等）、DOM XSS、原型污染、不安全随机数
- Java：常见 SQL 拼接、命令执行（Runtime.exec/ProcessBuilder）、XXE/HQL 风险等（启发式）

> 说明：项目级别还支持（可选）向量库导入，用于相似代码与上下文检索；单文件模式不会加载嵌入模型，启动更快。

## API 列表
- `GET  /health` 健康检查
- `GET  /api/models` 拉取可用模型（按提供商自动规范化 base_url）
- `POST /api/configure` 更新 Key/Base/Model（JSON）
- `POST /api/audit` 单文件审计（multipart：`file`，可选 `api_key/api_base`）
- `POST /api/audit/project` 项目审计（multipart：`project`，可选 `api_key/api_base`）
- `GET  /ui` 前端页面

## 运行建议
- 生产建议使用多 worker：
```bash
uvicorn backend.app:app --host 0.0.0.0 --port 8000 --workers 2
```
- 根据机器与配额适当调高 `SCAN_CONCURRENCY`、`AI_CONCURRENCY`，并观察资源与速率限制

## 常见问题
- 首次运行下载嵌入模型较慢？
  - 仅项目模式导入向量库会触发下载；单文件模式默认不会下载/加载嵌入模型
- Windows 上出现 HuggingFace symlink 警告？
  - 可忽略；或以管理员/开发者模式运行
- `/api/models` 拉取失败？
  - 检查 `api_key/api_base` 是否正确；无需在前端拼 `/v1`，后端会统一规范化

---

如果你需要进一步扩展更多语言/框架规则，或接入其它 OpenAI 兼容平台，欢迎提交 Issue / PR。
