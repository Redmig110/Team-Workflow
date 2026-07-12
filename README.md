<div align="center">

# Team Workflow Console

**面向 Windows 的本地优先 Team 工作流控制台**

统一管理空间、账号轮换、顺序队列、浏览器身份快照、CPA Management 与 Sub2API 推送。

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Windows](https://img.shields.io/badge/Platform-Windows-0078D4?logo=windows11&logoColor=white)](#运行环境)
[![FastAPI](https://img.shields.io/badge/FastAPI-localhost-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-136%20passed-2E7D32)](#测试)
[![License: MIT](https://img.shields.io/badge/License-MIT-111111.svg)](LICENSE)

</div>

## 项目概览

Team Workflow Console 将原本分散的账号、空间和运行配置收敛到一个仅监听本机回环地址的网页控制台。应用通过 SQLite 保存业务状态，通过 Windows Data Protection API (DPAPI) 加密敏感值，并用全局串行队列执行完整工作流。

| 能力 | 说明 |
| --- | --- |
| 空间任务 | 每个空间独立维护当前账号、下一账号、轮换次数和运行状态 |
| 邮箱库存 | 按需搜索与分配，不会一次性加载大规模邮箱文件 |
| 别名轮换 | 按 `+1` 到 `+5` 顺序使用，耗尽后自动切换下一主邮箱 |
| 顺序队列 | 全局单任务执行，支持暂停、重排、停止、重试与断点恢复 |
| 一致身份 | 单次运行生成一个浏览器指纹和代理快照，并贯穿完整流程 |
| 双目标推送 | 工作流完成后可分别推送到 CPA Management 和 Sub2API |
| 加密备份 | 数据库快照、完整性校验、DPAPI 解密验证和受控恢复 |
| 本地控制台 | 仅绑定 `127.0.0.1`，写操作同时校验同源与启动期请求令牌 |

## 界面与流程

控制台围绕四个工作面组织：

1. **空间任务**：建立空间与账号对的绑定，批量加入队列，处理额度用完或账号失效。
2. **账号库**：一次导入邮箱库存，按邮箱搜索，查看主邮箱的别名使用进度。
3. **执行队列**：观察八阶段进度，调整顺序，暂停领取任务或请求停止当前运行。
4. **设置**：配置代理、PAT、推送目标、输出目录以及加密备份。

```text
邮箱库存 ──按需分配──> 空间账号对 ──加入队列──> 单任务执行器
                                               │
                                               ├─ 固定指纹与代理快照
                                               ├─ 登录 / 邀请 / 退出 / 注册
                                               ├─ PAT 与 CPA 生成
                                               └─ Management / Sub2API 推送
```

## 运行环境

- Windows 10 或 Windows 11
- Python 3.11 或更高版本
- Chromium（由 Playwright 安装）

敏感数据使用当前 Windows 用户的 DPAPI 保护，因此数据库和加密备份不能简单复制到其他 Windows 用户下解密。

## 快速开始

```powershell
$ErrorActionPreference = 'Stop'
git clone 'https://github.com/Redmig110/Team-Workflow.git'
Set-Location '.\Team-Workflow'

python -m venv '.venv'
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r '.\requirements.txt'
.\.venv\Scripts\python.exe -m playwright install chromium
```

启动本地控制台：

```powershell
$ErrorActionPreference = 'Stop'
.\.venv\Scripts\python.exe '.\run_web.py'
```

浏览器默认打开[本地控制台地址](http://127.0.0.1:8765/)。以下入口等价：

```powershell
$ErrorActionPreference = 'Stop'
.\.venv\Scripts\python.exe -m team_protocol web
.\.venv\Scripts\python.exe -m team_protocol gui
```

`gui` 是网页控制台的兼容别名；项目不再维护独立桌面 GUI。

## 数据安全

| 数据 | 默认位置 | 保护方式 |
| --- | --- | --- |
| 应用数据库 | `%LOCALAPPDATA%\TeamWorkflowConsole\console.db` | 敏感字段使用 Windows DPAPI 加密 |
| 加密备份 | 项目目录下的 `backups\` | 完整性校验 + DPAPI 用户绑定 |
| CPA / session 导出 | 项目目录下的 `output\` | 明文凭据边界，仅在显式导出时产生 |
| 邮箱源文件 | 用户选择的位置 | 仅在显式导入时读取，不由应用自动删除 |

仓库的 `.gitignore` 默认排除以下内容：

- 邮箱或账号 TXT；
- HAR、CPA、session、PAT 与工作流 JSON；
- SQLite 数据库、加密备份、运行输出和日志；
- 本地迁移状态、内部分析报告与验收产物。

> [!IMPORTANT]
> `output\` 中的 CPA/session 文件属于明文凭据。只在需要时生成，用完后及时删除，禁止提交到版本控制。

## 账号轮换规则

- 邮箱库存只在用户搜索或实际分配时加载所需数据。
- 每个主邮箱最多使用五个别名：`+1`、`+2`、`+3`、`+4`、`+5`。
- 当前账号完成轮换后，下一账号提升为当前账号，并自动分配新的下一账号。
- `+5` 用完后，从下一可用主邮箱的 `+1` 继续。
- 子号不可用时仅替换对应子号；邮箱凭据失效时停用整个主邮箱库存。
- 网络、代理、限流或 OTP 超时不会被误判为邮箱失效。

## 工作流阶段

```text
01 旧号登录
02 邀请新号
03 旧号退出
04 新号注册
05 创建令牌
06 生成 CPA
07 推送 Management
08 推送 Sub2API
```

队列在每个阶段保存 checkpoint。进程异常退出后可以恢复同一次运行，避免重复邀请、重复退出或重复创建远端资源。

## 命令行工具

除网页控制台外，项目还保留独立的协议工具：

| 命令 | 用途 |
| --- | --- |
| `python -m team_protocol analyze` | 从 HAR 提取协议时间线 |
| `python -m team_protocol convert` | 将 HAR/session 转为 CPA 格式 |
| `python -m team_protocol push` | 校验并推送 CPA 文件 |
| `python -m team_protocol invite` | 执行单步邀请 |
| `python -m team_protocol leave` | 执行单步退出空间 |
| `python -m team_protocol create-token` | 创建 PAT |
| `python -m team_protocol refresh-session` | 刷新会话 |

查看任一命令的完整参数：

```powershell
$ErrorActionPreference = 'Stop'
python -m team_protocol --help
python -m team_protocol web --help
```

## 项目结构

```text
Team-Workflow/
├─ team_protocol/
│  ├─ registrar_runtime/    # OTP、注册、代理与浏览器流程
│  ├─ web_static/           # 本地控制台前端
│  ├─ database.py           # SQLite 模型、事务与轮换规则
│  ├─ task_queue.py         # 全局顺序队列与恢复
│  ├─ workflow.py           # 八阶段工作流
│  └─ web_console.py        # FastAPI 控制台服务
├─ tests/                   # 单元与服务层回归测试
├─ run_web.py               # 推荐启动入口
└─ requirements.txt
```

## 测试

```powershell
$ErrorActionPreference = 'Stop'
$env:PYTHONDONTWRITEBYTECODE = '1'
python -B -m unittest discover -s '.\tests' -v
```

当前测试覆盖数据库事务、并发分配、账号轮换、迁移与备份、DPAPI、队列恢复、Web API、指纹一致性以及双目标推送。

## 隐私发布检查

提交代码前建议执行：

```powershell
$ErrorActionPreference = 'Stop'
git status --short
git diff --cached --name-only
git grep -n -I -E 'BEGIN .*PRIVATE KEY|github_pat_|ghp_|Bearer [A-Za-z0-9._~-]{20,}' --cached
```

确保暂存区仅包含源码、测试、依赖清单和公开文档，不包含任何运行数据或真实账号信息。

## License

本项目采用 [MIT License](LICENSE)。
