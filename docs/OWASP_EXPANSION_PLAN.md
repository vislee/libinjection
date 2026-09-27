# OWASP Top 10 攻击面补齐规划（libinjection 4.0 提案）

> 日期：2026-09-27　状态：**全部完成**（P0-P4，2026-09-27），版本 4.0.0 定稿
> 前置成果：3.10.0 已覆盖 SQLi/XSS（A03 核心两类），自建+公开数据集准召 ≥95%，
> 拥有成熟工程框架：归一化管线、数据驱动测试、283 项单元测试、覆盖率门禁 97.78%、
> 公开数据集盲测工具链（`scripts/eval_public_datasets.py`）。
> 本规划回答两个问题：**OWASP Top 10 里还有哪几类能用"输入检测库"补齐？怎么做才不失守
> 既有的性能与精度底线？**

---

## 1. OWASP Top 10 (2021) 与字符串检测库的能力边界

先划清边界——不是所有类别都能靠"检查输入字符串"解决，诚实划界比堆功能重要：

| 类别 | 名称 | 字符串检测可覆盖？ | 本规划动作 |
|---|---|---|---|
| A01 | 失效的访问控制 | **部分**：路径穿越/目录列举/敏感文件读取在请求串中有明显指纹（IDOR 等行为类不可） | ✅ P1：LFI/路径穿越模块 |
| A02 | 加密机制失效 | ✗（服务端设计问题，不体现在输入串） | ➖ 明确不支持，文档给检测建议 |
| A03 | 注入（核心类） | **是**：SQLi/XSS 已覆盖；还有 OS 命令注入、SSTI、LDAP、XPath、NoSQL、JNDI(Log4Shell)、PHP 代码注入 | ✅ P1–P3：7 个新检测类 |
| A04 | 不安全的设计 | ✗（架构问题） | ➖ 不支持 |
| A05 | 安全配置错误 | **微量**：CRLF/HTTP 响应拆分、日志注入探针在输入中可见；其余（缺安全头、默认口令）不可 | ✅ P1：CRLF/Header 注入 |
| A06 | 易受攻击的组件 | ✗（需要版本指纹，属 SCA 工具）——但 **Log4Shell 类利用探针**在输入串中可见 | ✅ 归入 A03 的 JNDI 模块；版本盘点建议配 SCA |
| A07 | 身份识别与认证失败 | ✗ 本质行为类（撞库、弱口令、会话固定）；仅认证绕过类 SQLi/XSS 探针已被现有引擎覆盖 | ➖ 已被现有能力间接覆盖 |
| A08 | 软件和数据完整性故障 | **部分**：不安全反序列化（Java/PHP/Python/Ruby 序列化魔术字节）在输入串中可识别 | ✅ P2：反序列化探针模块 |
| A09 | 日志与监控失败 | ✗（流程问题）；日志注入探针归入 A05 条目 | ➖ 日志注入归 P1 CRLF 模块 |
| A10 | SSRF | **是**：云元数据地址、内网 IP、危险 scheme 在参数值中有强指纹 | ✅ P1：SSRF 模块 |

结论：**可新增 9 个检测类**（命令注入、路径穿越/LFI/RFI、SSRF、SSTI、LDAP、XPath、
NoSQL、反序列化、CRLF+日志注入+JNDI 合并的"结构化探针"类），
其余 6 类（A02/A04/A05 大部/A06/A07/A09）明确不做，文档中给出对应的正确工具建议
（SCA、CSP/安全头基线、多因素、行为风控、SIEM）。

## 2. 设计原则（全部沿用 3.10.0 已验证的方法论）

1. **零依赖、O(n)、无回溯正则**：字符类预过滤表 → 短签名族匹配 → 白名单降噪，
   单核百万行/秒的底线不破。
2. **归一化优先**：所有新模块共享既有解码层（URL ×3 迭代、HTML 实体、CSS 转义），
   新增"反斜杠统一、`\x`/`\uNNNN`、Base64 探测"等按需归一化，先解码后匹配。
3. **签名必须配降噪**：本轮公开语料盲测的教训——`url(javascript` 这类强签名可以
   直接做；`$`、`|`、`../` 这类弱特征必须组合判定（分隔符+命令词/重复次数/边界），
   每个模块自带误报语料校准。
4. **数据管线化**：签名数据像 `fingerprints.txt` 一样放 `data/*.txt` + 生成脚本，
   不手写进 C；每类附公开语料来源（SecLists/PayloadsAllTheThings/CSIC），
   fixture 固化典型向量。
5. **工程门禁不降**：每模块单元测试 + fixture、行覆盖 ≥95%、`make check` 全绿、
   公开数据集盲测进 `eval_public_datasets.py`。

## 3. 各模块设计

### 3.1 OS 命令注入（A03）— 模块 `libinjection_cmd`

- **预过滤**：串内含 `` ; | & $ ` \n %0a `` 任一才进入主匹配（绝大多数文本直接排除）。
- **判定**（满足其一）：
  - 元字符 + 已知命令词（分 OS 词表：POSIX `cat/ls/id/whoami/wget/curl/nc/bash/
    python/sleep/chmod/rm…`；Windows `dir/type/del/powershell/cmd…`）；
  - 命令替换结构 `$(...)`、`` `...` ``、`<(...)`,内部含命令词；
  - 管道/分号边界后跟空格+命令词；换行注入 `%0a` + 命令；
  - 经典混淆：`base64 -d|sh`、`printf \x`、`xxd -r`、`{echo,}>>`、PowerShell
    `IEX/Invoke-Expression/DownloadString`。
- **降噪**：URL 里裸 `&`/`|`、价格 `$1.99`、shell 提示符文本不告警（无命令词邻接）。
- 误报风险：**中**。命令词表是精度的关键，需要白名单校准轮。
- 数据源：SecLists `Fuzzing/command-injection-commix.txt`、PayloadsAllTheThings。

### 3.2 路径穿越 / LFI / RFI（A01/A03）— 模块 `libinjection_trav`

- **归一化**：双轮 URL 解码 + 反斜杠统一 + UTF-8 超长编码展开（`%c0%af`→`/`）。
- **判定**：
  - `../` 或 `..\` 出现 ≥2 次；或 1 次且落在参数值边界；
  - 敏感路径后缀：`/etc/passwd|shadow|hosts`、`boot.ini`、`win.ini`、
    `system32/config/sam`、`/proc/self/environ`、`~/.ssh/id_rsa`、`.aws/credentials`；
  - 包装协议：`php://filter|input`、`data://text`、`file://`、`zip://`、`phar://`、
    `expect://`、`jrtplib`；RFI：参数值本身是 `http(s)://` 外域 URL + `.txt|.php` 结尾
    （标记为可疑，不直接告警，给评分）。
- 误报风险：**低-中**（changelog 里 `../` 少见；RFI 评分需要阈值）。
- 数据源：SecLists `Fuzzing/LFI/LFI-Jhaddix.txt`（32KB 精选）、CSIC 异常流量的
  traversal 桶（公开盲测中基线为 0%，正好做专属评测）。

### 3.3 SSRF（A10）— 模块 `libinjection_ssrf`

- **判定**（值本身是 URL/主机形态时，避免散文误报）：
  - 云元数据：`169.254.169.254`、`100.100.100.200`、`metadata.google.internal`、
    `169.254.170.2`；
  - 回环/内网：`localhost`、`127.0.0.0/8`、`0.0.0.0`、`10.*`、`192.168.*`、
    `172.16-31.*`、`[::1]`、`*.internal|local`；
  - 编码绕过：十进制 `2130706433`、八进制 `0177.0.0.1`、十六进制 `0x7f000001`、
    略写 `127.1`；
  - 危险 scheme：`gopher://`、`dict://`、`file://`、`tftp://`。
- 误报风险：**中**（IP 出现在文档/版本号里）——锚定"值即 URL"的边界判定是关键。
- 数据源：PayloadsAllTheThings SSRF intruder 清单 + 上述常量表手写（稳定、小）。

### 3.4 SSTI 服务端模板注入（A03）— 模块 `libinjection_ssti`

- **判定**：
  - 模板标记存在（`{{...}}`、`${...}`、`<%=...%>`、`#{...}`、`{%...%}`）**且**内含
    危险语义：算术探针（`7*7`、`7*'7'`）、属性爬升（`__class__`、`constructor`、
    `config`、`self.`、`mro`）、函数调用（`popen`、`read()`、`import`、`range(`）；
  - 识别用 SecLists `template-engines-special-vars.txt`。
- **降噪**：纯变量占位 `{{name}}`/`${field}` 判良性（邮件模板常见）。
- 误报风险：**中**（前端模板串常见，语义判定是关键）。

### 3.5 NoSQL 注入（A03）— 模块 `libinjection_nosql`

- **判定**：括号/引号上下文中的 `$` 操作符（`[$ne]`、`["$gt"]`、`{$regex:`、
  `$where`、`$fn`、`$func`、`$where` + JS 体）、布尔探测 `|| 1==1`、
  PHP-Mongo 注入 `'; return true; var x='`。
- **降噪**：裸 `$ne`/`$gt`（邮件签名、价格区间）不告警，必须带括号/JSON 上下文。
- 数据源：SecLists `Fuzzing/Databases/SQLi/NoSQL.txt`（公开盲测已下载）。

### 3.6 LDAP / XPath 注入（A03）— 模块 `libinjection_ldap`（合一个模块两类签名）

- **LDAP**：`)(` 边界 + 过滤符组合（`*)(uid=*))`、`*)(objectClass=*`、`(|(`、
  `%28%29` 编码形态）；纯 metachar 模糊串（`LDAP.Fuzzing.txt`）只做评分不做告警。
- **XPath**：`//tag[`、`'] | //`、`count(/*`、`string-length(`、`' or '1'='1` 已被
  SQLi 引擎覆盖部分不再重复。
- 误报风险：**中高**（括号星号在文本中常见）→ 必须 `)(` 双字符边界锚定。
- 数据源：SecLists `Fuzzing/LDAP.Fuzzing.txt`、PayloadsAllTheThings LDAP/XPath。

### 3.7 反序列化探针（A08）— 模块 `libinjection_deser`

- **判定**（魔术字节/特征串，天然低误报）：
  - Java：`rO0AB`（`aced0005` 的 Base64 前缀）、`|org.apache.commons.`、
    ysoserial gadget 链特征（`org.apache.xalan`、`Runtime.getRuntime`）；
  - JNDI/Log4Shell：`${jndi:` + `ldap|rmi|dns|iiop|corba`、嵌套混淆
    `${${lower:j}ndi`、`${::-j}ndi`（近零误报，直接告警）；
  - PHP：`O:\d+:"` 序列化对象头；
  - Python pickle：Base64 `gASV`（`\x80\x04` 魔术）、`copyreg`、`__reduce__`；
  - Ruby：`BAh`（`\x04\x08`）、`Gem::`。
- 误报风险：**低**。
- 数据源：PayloadsAllTheThings Deserialization、ysoserial 常见 gadget 名单。

### 3.8 CRLF / Header / 日志注入（A05/A09 交界）— 模块 `libinjection_crlf`

- **判定**：`%0d%0a`（及解码后）后跟头部语法（`HTTP/1.`、`Location:`、
  `Set-Cookie:`、`Content-`）→ 响应拆分；裸 `\n` + 伪日志等级
  （`[error]`、`INFO:`）+ 伪造结构 → 日志注入（评分制）。
- 误报风险：**低**（要求 CR+LF 成对 + 冒号结构）。

### 3.9 代码注入探针（A03 收尾）

- `<?php`、`<?=`、`<%@`、JSP `<%`（白名单 `<?xml`）、`eval(`/`system(` 等仅当
  出现在"参数值形态"时告警；与 XSS 模块的 `<script` 判定互不重叠。
- 误报风险：**中**（`<%` 模板文本），放最后做。

## 4. API 设计

```c
/* 单类检测：与既有 libinjection_sqli/xss 同风格 */
int libinjection_cmd (const char* s, size_t len);
int libinjection_trav(const char* s, size_t len);
int libinjection_ssrf(const char* s, size_t len);
int libinjection_ssti(const char* s, size_t len);
int libinjection_nosql(const char* s, size_t len);
int libinjection_ldap(const char* s, size_t len);   /* 含 XPath */
int libinjection_deser(const char* s, size_t len);  /* 含 JNDI/Log4Shell */
int libinjection_crlf(const char* s, size_t len);

/* 一次解码、多类并行扫描（推荐接入方式） */
uint64_t libinjection_classify(const char* s, size_t len, uint64_t want_mask);
/* 返回 bitmask：BIT_SQLI | BIT_XSS | BIT_CMD | BIT_TRAV | BIT_SSRF | ... */
```

- 既有 API 一律不动（`libinjection_sqli/xss/url` 行为冻结，沿用 3.10.0 承诺）；
- `classify` 内部**只做一次归一化**，各类检测共享解码结果（避免每类重复解码的性能浪费）；
- 三个 URL 解码迭代、实体/CSS 转义助手从 sqli/xss 模块提为 `libinjection_normalize.c` 内部公共层。

## 5. 分阶段落地计划（每阶段独立可交付、可回滚）

| 阶段 | 内容 | 交付物 | 预估工作量 |
|---|---|---|---|
| **P0 基座 ✅ 已完成** | 提取共享归一化层（`libinjection_normalize.{h,c}`：`libinjection_urldecode` 实现迁入 + `libinjection_scan_url` 迭代解码驱动）；`libinjection_classify{,_url}()` 骨架（SQLI/XSS bitmask，表驱动，新类加一行即可注册，预留 bit2-9）；`sqli_url`/`xss_url` 重构到共享层；版本 3.11.0 | **行为零变化验证通过**：299 项单测全绿、四套官方样本全绿、run-benchmark 数字与重构前逐项一致、公开语料评测（CSIC XSS 100% 等）逐行一致、覆盖率 97.89% ≥95% | 1 天 ✅ |
| **P1 低误报高价值 ✅ 已完成** | 4 个模块落地（`libinjection_trav` 路径穿越/LFI、`libinjection_ssrf`、`libinjection_deser` 反序列化+JNDI、`libinjection_crlf`），注册进 classify bit 3/4/8/9；版本 3.12.0；reader 新增 `--trav/--ssrf/--deser/--crlf` 模式；盲测脚本按类扩展（新类基线自动标 n/a） | **红队召回 4×100%**（trav 23/23、ssrf 20/20、deser 16/16、crlf 8/8）；**CSIC 36,000 正常查询 FP=0**、benign-p1 全 0；CSIC other-attack 桶 0%→**80.9%**（380/470）；376 项单测 + 12 个 fixture 全绿；覆盖率 97.87% | 1 天 ✅ |
| **P2 中风险** | OS 命令注入、SSTI、NoSQL | 同上 + 命令词表/模板语义判定的白名单校准轮 | 3–5 天 |
| **P3 高风险收尾** | LDAP/XPath、代码注入探针 | 同上 + 两轮误报校准 | 3–5 天 |
| **P4 收尾** | `libinjection_classify` 全量接线、README/文档、版本 4.0.0、公开盲测总报告 | 全类联合评测报告 | 1–2 天 |

**每模块统一验收标准**（与 3.10.0 同门槛）：
1. 自建红队集召回 ≥95%（从对应公开 payload 清单采样 + 手工构造绕过变体）；
2. FP 语料误报 ≤1%（每模块专属良性语料：shell 脚本文本、含 `$`/`|` 的 URL、
   邮件模板、含 IP 的文档）；
3. 单元测试行覆盖 ≥95%，`make check` 全绿；
4. 进入 `run-benchmark.sh` 与 `eval_public_datasets.py` 常设对比。

## 6. 测试与评测计划

- **单元测试**：`test_unit.c` 按模块分区（目标 283 → ~700 项断言）；
- **fixture**：`tests/test-cmd-*.txt` 等按类命名（testdriver 需加前缀映射，属 P0）；
- **公开语料盲测**：`eval_public_datasets.py` 增加 per-class 语料注册
  （SecLists commix/LFI/template-engine/NoSQL/LDAP、PayloadsAllTheThings SSRF/反序列化、
  CSIC other-attack 桶变成 traversal 模块的主场——基线 0% 有很大提升空间）；
- **误报校准**：每模块建 `data/benign-<class>.txt`（含正常 shell 命令、URL、模板、
  日志行），进 `run-benchmark.sh` 常设对比；
- **对抗回归**：每条修复过的绕过都固化为 fixture（沿用本轮 `test-xss-redteam-*` 的做法）。

## 7. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 命令注入/模板类误报失控 | 用户被迫关模块 | 评分制（元字符+命令词双条件）先行，宁可漏不可滥；白名单校准轮设为必经环节 |
| 性能退化（多类并行扫描） | 高并发场景掉 QPS | 单次解码共享；每类前置 O(1) 字符预过滤表；`test_speed_*` 基准纳入 check |
| 签名数据膨胀 | 二进制变大 | 数据走生成脚本压缩（前缀树/字符表），目标全部新增 ≤200KB |
| 语义超界（把库做成 WAF） | 维护负担 | 冻结边界：只做"输入串可判定"的类别，行为类明确拒绝并文档化 |
| 公开语料过时误导调参 | 过拟合老 payload | 红队集每季度手工补充现代绕过；盲测结论按"同语料对比"而非绝对值 |

## 8. 明确不做（及建议的正确工具）

| OWASP 类别 | 为什么不做 | 建议配套 |
|---|---|---|
| A02 加密失效 | 服务端实现问题，输入串无信号 | TLS/证书基线扫描、代码审计 |
| A04 不安全设计 | 架构问题 | 威胁建模、设计评审 |
| A05 大部/配置错误 | 需要 Response 头/配置上下文 | 安全头基线（CSP/HSTS）、配置审计 |
| A06 组件过时 | 需要依赖清单 | SCA（OWASP Dependency-Check 等）；Log4Shell 利用探针已在本库覆盖 |
| A07 认证失败 | 行为类，需会话/频率上下文 | 多因素、限流、撞库风控 |
| A09 日志监控缺失 | 流程问题 | SIEM/SOC；日志注入探针已在本库覆盖 |


---

## 9. P1 实施记录（2026-09-27）

### 交付物
- `libinjection_trav.{h,c}`：`../`/`..\`/编码变体（%2e%2e、..%2f、双重编码、UTF-8 超长
  `%c0%af`）≥2 次告警；敏感路径表（/etc/passwd、win.ini、id_rsa、.aws/credentials…）；
  包装协议（php://、file://、zip://、phar://、expect://）；**null 字节**（字面/%00）与
  **编辑器备份后缀**（`page.asp~`）两条盲测驱动的规则；
- `libinjection_ssrf.{h,c}`：云元数据地址（AWS/GCP/ECS/阿里）+ `gopher/dict/tftp` scheme
  无条件告警；回环/内网目标（含十进制 2130706433、十六进制 0x7f000001、八进制、`127.1`
  略写）仅在 URL 位形（`=`/`//`/引号之后）告警——`ping 127.0.0.1`、`version 10.04` 等
  散文形态不触发；
- `libinjection_deser.{h,c}`：Java 序列化 Base64 魔术 `rO0AB`、pickle `gASV`、ysoserial
  与常见 gadget 类名、PHP `O:<n>:"` 对象头、`__reduce__`；JNDI/Log4Shell 覆盖
  `${jndi:`、`${`+`jndi` 嵌套及 `${::-j}ndi`/`${lower:n}di` 分裂混淆；
- `libinjection_crlf.{h,c}`：CR-LF 对（字面/%0d%0a/%0a%0d，含解码后 `

`）+ 48 字符
  内的 HTTP 头语法；另支持 LF-only 服务器的 `
HTTP/1.` 形态。

### 公开语料实测（`eval_public_datasets.py`）
| 语料 | 结果 |
|---|---|
| SecLists LFI-Jhaddix（930 行） | 27.1%——漏报大头为"要尝试的文件路径字典"（如 `/apache2/logs/access.log`），属清单性质、不可签名，与 SQLi 清单中完整语句同理 |
| CSIC other-attack 桶（470 请求） | 0%（基线无此能力）→ **80.9%**；剩余漏报以 RFC 1918 之外的内网主机名与路径字典为主 |
| CSIC 正常流量（36,000 查询） | 四类 FP 均 **0** |

### 校准过程要点
- ssrf 的前缀目标（`192.168.`/`10.`）边界规则需区分"数字继续"（IP）与"字母继续"
  （仅 `//` 后的 hostname 位形才算）；
- 喂给检测器的输入契约是**参数值**，直接灌完整 HTTP 请求（含 `Host: localhost` 头）
  不在其列——评测脚本统一先提取 URI；
- 单元测试里三处手写长度参数越界（34 传 35、38 传 42）只在 -O3 下暴露，
  已改为 strlen 包装——教训：测试代码同样要做越界审查。


## 9. P2/P3 实施记录（2026-09-27）

### 交付物
- `libinjection_cmd.{h,c}`（bit 2）：元字符（分号/管道/取反/美元/反引号/换行及编码
  %0a）与命令词的邻接判定（POSIX+Windows 约 110 个命令词、`&sort=` 键值抑制、
  `/bin/cat` 路径段跳过、`$(cmd)`/反引号替换窗口、`/dev/tcp`、`base64 -d|sh`、
  PowerShell `IEX`/`DownloadString`）；
- `libinjection_ssti.{h,c}`（bit 5）：模板标记（双花括号/美元花括号/<%/#}/{%%）64 字符
  窗口内的危险语义（`7*7` 探针、`__class__/__mro__` 属性爬升、`forName/getClass/
  popen/phpinfo`），外加 `{{config}}`/`{{ config }}` 专属规则；普通占位符良性；
- `libinjection_nosql.{h,c}`（bit 6）：Mongo 操作符的括号/JSON/引号/等号上下文判定
  （`[$ne]`、`{"$gt":""}`、`{$where:`）、`||` 布尔探针（含引号相等组合与大小写变体）、
  PHP 风格 `'; return`；
- `libinjection_ldap.{h,c}`（bit 7）：LDAP `)(` 过滤器边界 + 属性赋值与 `|(`、`&(` 树；
  XPath 节点联合（`'] | //`）、`count(/*`、`//user[` 等查询专属形态；
- `libinjection_code.{h,c}`（bit 10）：`<?php`/`<?=`/`<%@`、`eval(base64`、带引号的
  `eval(` 与 `system(`、`shell_exec(`；`<?xml` 天然良性。

### 实测结果
| 语料 | 结果 |
|---|---|
| 红队集（cmd 22 / ssti 10 / nosql 12 / ldap 8 / code 8） | 5 类全部 **100% 召回** |
| benign-p23 专用良性集（20 行） | 5 类 FP 全 **0** |
| CSIC 2010 正常流量（36,000 查询） | 5 类 FP 全 **0**（cmd 从初始 84 条误报校准至 0） |

### 校准过程要点（4 个逻辑缺陷在盲测校准中发现并修复）
1. cmd 混淆签名（/dev/tcp 等）原本放在元字符预过滤之后导致永不执行——签名检查前移；
2. `$(cmd)` 替换检查同样被预过滤拦截——前移（`$(` 在正常输入中罕见，成本可忽略）；
3. `&sort=asc` 型查询键触发“& + 命令词”误报——meta_after 增加键值抑制；
4. meta_after 对分号后无命令词的散文也告警——收紧为元字符后必须紧跟命令词。

### 状态
- 全部 11 个检测类已在 `libinjection_classify` 注册完毕；P4 仅剩文档收尾、
  版本定稿（4.0.0）与全量总报告。


---

## 10. P4 实施记录（2026-09-27）

- 版本定稿 **4.0.0**（11 个检测类全部就位，构成大版本能力边界）；
- README 重写：11 类能力表、完整 API、classify 快速上手、构建/测试/评测/覆盖率
  命令、嵌入清单；
- 全量总报告 `docs/FINAL_REPORT.md`：3.9.2 -> 4.0.0 全程指标、边界与生产建议；
- 最终验证：`make -C src check` 450 项测试 + 全部 fixtures + 4 套官方样本全绿；
  `make coverage` 98.04% 通过门禁；`make benchmark` 11 类召回/误报全达标。
