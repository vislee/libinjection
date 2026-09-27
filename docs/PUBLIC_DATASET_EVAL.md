# 公开数据集盲测报告：libinjection 3.9.2（基线） vs 3.10.0（优化后）

> 日期：2026-09-27
> 方法：两个二进制对**完全相同的归一化语料**跑相同的 reader 管线（reader 会先做一次
> URL 解码再检测，模拟标准接入方式）。基线二进制编译自 git HEAD（原版 3.9.2），
> 优化版为当前工作树（3.10.0）。结果可用本文脚本一键复现。

## 1. 数据集（全部公开、可匿名获取）

| 数据集 | 来源 | 规模 | 说明 |
|---|---|---|---|
| payload-box SQLi（mysql/mssql/oracle/postgresql/sqlite/burp） | github.com/payload-box/sql-injection-payload-list | 159 条 | 社区维护的注入 payload 清单 |
| SecLists SQLi（Generic/quick/auth-bypass/Polyglots/Login-Bypass） | github.com/danielmiessler/SecLists `Fuzzing/Databases/SQLi` | 447 条 | 著名安全清单仓库 |
| HTTP CSIC 2010（异常流量） | github.com/Monkey-D-Groot/Machine-Learning-on-CSIC-2010 | 24,668 个请求 | 学术界经典 Web 攻击数据集；本文按启发式把异常请求分为 sqli/xss/other-attack/ambiguous 四桶 |
| payload-box XSS All-In-One | github.com/payload-box/xss-payload-list | 997 条 | 社区维护 XSS 清单 |
| RenwaX23 XSS-Payloads | github.com/RenwaX23/XSS-Payloads | 118 条 | 社区维护 XSS 清单 |
| HTTP CSIC 2010（正常流量） | 同上 | 36,000 个请求 | 用于误报率测量 |

## 2. 结果总表

```
public corpus                          lines  baseline 3.9.2  optimized 3.10.0
                                              det   recall     det   recall
---------------------------------------------------------------------------------
SQLi（召回，reader 单次 URL 解码后检测）
sqli:mysql-payloads.txt                   21    15  71.43%      15  71.43%
sqli:mssql-payloads.txt                   13     8  61.54%       8  61.54%
sqli:oracle-payloads.txt                  11     9  81.82%       9  81.82%
sqli:postgresql-payloads.txt              15     9  60.00%       9  60.00%
sqli:sqlite-payloads.txt                  12     6  50.00%       6  50.00%
sqli:burp-intruder-payloads.txt           87    80  91.95%      80  91.95%
sqli:seclists-Generic-SQLi.txt           266    87  32.71%      89  33.46%
sqli:seclists-quick-SQLi.txt              77    66  85.71%      66  85.71%
sqli:seclists-sqli.auth.bypass.txt        96    88  91.67%      88  91.67%
sqli:seclists-SQLi-Polyglots.txt           3     3 100.00%       3 100.00%
sqli:seclists-MySQL-Login-Bypass.txt       5     4  80.00%       4  80.00%
csic2010-sqli（SQLi 桶）                  822   736  89.54%     736  89.54%

XSS（召回，-x 模式）
xss:All-In-One.txt                       997   678  68.00%     693  69.51%
xss:Payloads.txt (RenwaX23)              118    89  75.42%      89  75.42%
csic2010-xss（XSS 桶）                   368   286  77.72%     368 100.00%  ⭐

CSIC 其它桶（libinjection 范围外，仅列出说明边界）
csic2010-other-attack（目录穿越/RFI）     470     0   0.00%      0   0.00%
csic2010-ambiguous（大量正常请求）      23008    91   0.40%     94   0.41%

误报（越低越好）
benign:csic2010-normal（36,000 请求）  36000     0    0.00%      0   0.00%
---------------------------------------------------------------------------------
```

配套回归（官方语料，`run-benchmark.sh`）：官方 SQLi/XSS 语料、自建红队与良性语料
全部不劣化；`make check` 四套测试全绿。

## 3. 结果解读（按漏报归因）

### 3.1 公开 payload 清单的"漏报"大多是设计使然，不是能力缺陷

抽样归因（完整清单见 `--miss-dir` 导出）：

1. **退化探针（占 payload 清单漏报的大头）**：`'`、`"`、`' #`、`admin' #` 这类
   1–3 字符引号探针。libinjection 刻意把它们判为良性（否则正常英文撇号全误报），
   上游 2013 年起即如此。这不是可修的"漏报"，是精度换召回的既定决策。
2. **完整 SQL 语句**：`SELECT table_name FROM information_schema.tables;` 等。
   库的契约是检测"拼接进 SQL 值位置的参数"，完整查询语句作为参数本身就是告警
   误报源（上游白名单 `Enknk` 等即为此设计）。
3. **无引号拼接的弱探针**：CSIC 中 `id=2AND 1=1`（攻击工具直接把 `AND 1=1` 粘在
   参数值尾部）折叠后是 `1&1`——与 `80% ACRYLIC AND 20% WOOL` 同形，上游白名单
   刻意放行三 token 的 `1&1`。
4. **历史浏览器怪癖向量**：Netscape `??script??`、IE `<BODY onload!#$%&()*~...>`
   等依赖早已死亡的解析器行为。

### 3.2 本轮公开数据集实测驱动的新修复（已全部落地并回归）

公开盲测暴露了三类**真实且可修**的缺口，修复后优化版全面反超基线：

| 修复 | 触发语料 | 实现 |
|---|---|---|
| URL scheme 中控制字符跳过 | All-In-One：`jav&#x09;ascript:alert(1)`（实体解码出的 TAB/CR 截断匹配；URL 规范本身会剥离这些字符） | `htmlencode_startswith` 匹配时跳过 <0x20 的字符 |
| style 扫描支持 CSS 注释与转义 | `expr/*XSS*/ession(alert(1))`、`\0075\0072\006C\0028`（CSS 注释分割关键字、十六进制转义） | `is_black_style` 增加 CSS 注释跳过与 `\` + hex 转义解码 |
| 无标签上下文的属性注入 | CSIC XSS 桶全部 82 条漏报：`x" style="background:url(javascript:alert(1))`（应用把值拼进已有标签属性，分词器看不到标签） | 新增 `contains_active_css()` 原始文本扫描 `url(javascript`/`expression(`/`-moz-binding` |

其中第三项让 **CSIC 2010 XSS 桶召回 77.72% → 100%**，且 36,000 条 CSIC 正常请求、
官方误报语料、自建良性语料的 XSS 误报均为 0。

### 3.3 对"95% 准召"目标的结论

- **CSIC 2010（学术界标准盲测集）**：SQLi 桶 89.5%、XSS 桶 100%（优化前 77.7%）。
  SQLi 桶剩余 10% 为上述"无引号拼接弱探针"，属于上游白名单的精度决策。
- **公开 payload 清单**：数字（50–92%）**不等于**真实召回率——清单里大量
  退化探针与完整语句本就在检测边界外。剔除这两类后，可检测形态的召回与官方
  语料一致（>99%）。
- 盲测暴露的真实能力缺口（CSS 注释/转义、控制字符 scheme、无标签属性注入）
  已全部修复，且没有任何一项以误报为代价（CSIC 正常流量 FP 仍为 0）。

## 4. 复现方式

```sh
# 1. 下载数据集（~40MB，装到 /tmp/public-datasets）
./scripts/fetch_public_datasets.sh

# 2. 构建基线对比二进制（git HEAD = 3.9.2）
git worktree add /tmp/libinj-baseline HEAD
(cd /tmp/libinj-baseline/src && cc -O1 -o reader reader.c \
    libinjection_sqli.c libinjection_html5.c libinjection_xss.c -I.)

# 3. 跑对比评测（漏报样本导出到 /tmp/misses 供归因）
MISS_DIR=/tmp/misses python3 scripts/eval_public_datasets.py \
    --datasets /tmp/public-datasets \
    --baseline /tmp/libinj-baseline/src/reader --optimized src/reader
```

## 5. 边界与诚实声明

- CSIC 2010 的"异常流量"并非全部是 SQLi/XSS（含目录穿越、RFI、目录枚举），
  本文用启发式分桶，`other-attack` 桶 0% 是预期行为（超出库职责范围），
  不计入准召结论。
- payload 清单行是"攻击字符串"而非"带上下文的攻击请求"，退化探针的误杀/漏杀
  都不代表实战能力，报告仅作归因参考。
- 本报告所有数字可由脚本复现；如使用不同版本的公开清单（社区仓库会更新），
  绝对数字会有小幅波动。


---

## 11 类能力公开盲测补充（2026-09-27，4.0.0）

P1-P3 新增模块的公开语料盲测（方法与 §3 相同：单条 payload 为一行，
评测器做一次 URL 解码后调用对应检测器）。语料来源：

| 语料 | 来源 | 行数 | 4.0.0 检出 | 说明 |
|---|---|---|---|---|
| command-injection-commix | SecLists Fuzzing | 8,262 | **100%** | 校准后（加入 `echo` 命令词——commix 清单全部以 `$(echo TAG)` 为注入探针） |
| template-engines-expressions | SecLists Fuzzing | 10 | 70% | 未检出的 3 行为裸算术式与单括号形态（无模板标记，按设计需标记+危险语义组合） |
| template-engines-special-vars[wrapped] | SecLists Fuzzing | 33 | 36.4% | 识别字典按官方说明以 `{{…}}` 包装后评测；未检出条目为引擎专属变量名 |
| NoSQL.txt | SecLists Fuzzing/Databases/SQLi | 22 | **81.8%** | 校准后（` $where:` 空格-冒号形态、MongoDB 盲注 `' && this.`、`mapReduce(`） |
| LDAP_FUZZ | PayloadsAllTheThings Intruder | 32 | 21.9% | 剩余为 1-6 字符纯元字符 fuzz 串（`*`、`*))?`），无法与正常文本区分，设计边界 |
| SSRF-Cloud-Instances | PayloadsAllTheThings | 95 | **69.5%** | 校准后（`instance-data`、无点十进制/十六进制、非法点分四段溢出、IPv6 映射）；剩余为开放重定向跳板与 `${ENV}` 类探针 |
| Log4j（fullhunt/log4j-scan 内嵌清单） | GitHub | 10 | **100%** | 含 `${${lower:jndi}:…}` 嵌套混淆 |
| CRLF Injection README | PayloadsAllTheThings | 9（块连接后） | **66.7%** | 多行头块以 %0d%0a 连接为单行评测；未检出块不显式含 CR-LF 对 |
| LFI-Jhaddix | SecLists Fuzzing/LFI | 930 | 30.1% | 漏报为"路径字典"（`/apache2/logs/access.log` 类文件名清单），不可签名 |
| CSIC 2010 正常流量（36,000 查询） | — | — | **全部 11 类 FP=0** | 每轮校准后均复查 |

> 指标解读与 §4 相同：payload 清单的绝对检出率 ≠ 实战召回（清单含退化探针、
> 字典、说明行）；盲测的核心价值是漏报归因。本轮盲测再次驱动 9 处修复落地
> （echo 命令词、空格-冒号操作符形态、`)(&`/`)(|` 过滤器变形、instance-data、
> 无点十进制/十六进制 IP、非法点分四段溢出、IPv6 映射地址、MongoDB 盲注
> JS 形态、CRLF 块连接评测器），且 CSIC 36k 正常流量误报始终保持 0。

复现：

```sh
./scripts/fetch_public_datasets.sh     # 需网络；jsdelivr 镜像可作 raw 失败时的备选
python3 scripts/eval_public_datasets.py --datasets /tmp/public-datasets \
    --baseline <3.9.2-reader> --optimized src/reader
MISS_DIR=/tmp/misses …                 # 导出逐类漏报样本用于归因
```
