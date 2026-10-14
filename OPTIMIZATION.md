# 代码优化交付说明

日期：2026-10-14。基于用户提供的 `webshell-watch` 目录制作，原始目录保持不变。
优化版保持纯 Python 标准库实现，不增加第三方运行依赖。

## 主要修改

| 部分 | 原问题 | 优化结果 |
|---|---|---|
| HTTP 分块消息 | 终止块边界搜索可能吞掉后续请求/响应；缺少末尾空行也被视为完整 | 统一解析数据和消费字节数，保留下一条报文，等待完整结束标记 |
| HTTP 输入限制 | 完整但超长的头部绕过长度检查；响应负长度导致异常消费；固定长度正文可超过收集上限 | 补齐边界检查，限制收集正文，同时保留有效报文的消费边界 |
| multipart 表单 | Content-Type 整体转小写破坏大小写敏感的 boundary；rstrip 会删除真实数据尾部 | 保留 boundary 大小写，只去掉分隔符前的一组 CRLF |
| 日志增量读取 | 半行和分批写入的 UTF-8 字符被提前拆开；文本偏移与字节长度混用 | 二进制偏移、完整行解码；半行缓存有上限；轮转和截断时清理旧缓存 |
| 离线日志 | 在线读取修复后需兼容无换行的最后一条记录 | 离线分析明确刷新末尾半行，在线监控继续等待换行 |
| IIS 实时监控 | 跳过历史内容时也跳过 #Fields 表头；运行后新建日期日志中的已有行被跳过 | 启动时读取表头，处理轮转后的字段变化；运行中新发现的日志从头读取 |
| 文件巡检性能 | 每个文件都重新构建已修改文件集合；新增文件重复执行内容扫描 | 使用本次变更标记判断，复用已经得到的内容命中结果 |
| 文件取证 | 哈希字段在告警写盘后才赋值，JSONL 中缺少哈希 | 在发出告警前填好哈希，订阅回调和持久化内容保持一致 |
| 基线状态 | 保存失败仍把内存标成已建立；更新基线后才生成告警导致丢失旧值 | 保存成功后再切换状态，失败可重试；使用旧基线生成变更证据 |
| 长期运行 | 日期在启动时固定；内存告警不断累积；去重受系统时间调整影响 | 每次写入按当天切换路径；守护进程默认保留最近 5000 条；去重使用单调时钟并维护过期顺序 |
| 启动入口 | Linux 默认配置路径错误；Windows 可能选中 Python 占位程序；Windows PowerShell 5.1 对无 BOM 中文脚本解析异常 | 修正根目录配置路径；验证解释器并共用查找逻辑；PowerShell 使用 UTF-8 BOM，Linux 脚本使用 LF |
| 资源管理与参数 | 配置文件未显式关闭；平台默认配置判断漏掉 --config= 和 -cPATH | 使用 with 关闭文件，兼容显式配置参数写法 |

## 验证结果

在 Windows、Python 3.12 环境完成：

- 原有 `selftest.py`：53/53 项通过。原测试中的 Unix 777 权限专项在 Windows 上按设计跳过，不计入这 53 项。
- 新增 `tests/test_regressions.py`：32/32 项通过，覆盖分块报文、multipart、半行、UTF-8 分批写入、轮转、截断、IIS 表头、基线失败、哈希落盘、跨天文件和去重等边界。
- 新增 Windows 入口检查：3 个 PowerShell 脚本语法通过；有效 Python 识别、无效路径拒绝和 Windows PowerShell 入口运行通过。
- `lint_check.py`：语法/导入静态检查通过；25 个引擎模块全部可导入。
- 全部 Python 源码 AST 语法检查、3 份 JSON 配置解析通过。
- `demo.py`、CLI 版本和规则列表命令退出码均为 0。
- Linux 入口完成配置路径、LF 和 BOM 静态检查；未在真实 Linux/systemd 环境运行。

没有安装服务或计划任务，没有启用抓包或 webhook；IIS、认证与事件日志检测使用合成样本验证，未在真实生产服务器执行部署验证。
完整命令输出在交付目录的 `validation-results.json`。

## 性能对比

使用同一 Python 解释器，对原版和优化版各运行 5 轮，模拟 5000 个文件全部发生变化，测量文件变更判定的 CPU 开销：

| 版本 | 5 轮耗时中位数 |
|---|---:|
| 原版 | 0.379796 秒 |
| 优化版 | 0.038531 秒 |

本次结果约为原版的 9.9 倍速度。测试替换了目录读取、内容匹配和告警输出，只用于比较变更判定逻辑，不代表完整磁盘扫描、检测引擎或生产吞吐量。

复现方式，在项目根目录运行：

```powershell
python benchmarks/scan_bookkeeping.py --project . --count 5000 --rounds 5
python benchmarks/scan_bookkeeping.py --project "原版目录" --count 5000 --rounds 5
```

## 使用方式

解压后进入项目根目录，先执行：

```powershell
python selftest.py
python -m unittest discover -s tests -v
python demo.py
```

Windows 使用：

```powershell
.\windows\wsp-windows.ps1 check
.\windows\wsp-windows.ps1 start --foreground
```

Windows 入口优先读取已安装的 `C:\ProgramData\webshell-watch\config.json`；不存在时读取项目根目录 `windows.json`。
可通过 `--config 配置路径` 显式覆盖。请按真实服务器配置 Web 根目录和日志路径。

如果 Python 不在 PATH 或命中了 WindowsApps 占位程序，可指定解释器后再运行入口：

```powershell
$env:WSP_PYTHON = 'C:\实际Python目录\python.exe'
.\windows\wsp-windows.ps1 check
```

Linux 使用项目根目录的 `linux.json`：

```bash
bash linux/wsp-linux check
```

新增 `output.max_history` 默认为 `5000`，只限制守护进程内存中的历史列表；累计统计和已经写出的日志不受影响。
设为 `0` 可恢复无限内存保留。离线 CLI 保留完整本次告警，方便导出。

服务安装和生产配置说明继续参考 README.md。
