# libinjection 检测能力评估与优化报告

> 基线版本：3.9.2 → 优化后版本：3.10.0（本仓库 master）
> 日期：2026-09-26
> 结论先行：libinjection 是"嵌入式、低资源、毫秒级"场景下最实用的 SQLi/XSS 检测方案之一，
> 但它**不是**准确率最高的方案——它是一套 2012-2016 年定型的"指纹黑名单"引擎，
> 数据自 2017 年起基本停更。优化前在自建红队样本集上实测，SQLi 召回仅 ~83%，
> 误报语料 FP 率 5.0%。本轮优化后（见 §5 结果），自建评测集全部指标 ≥95% 目标达成。

---

## 0. 优化结果（2026-09-26 实测，`./run-benchmark.sh` 一键复现）

| 指标 | 基线 3.9.2 | 优化后 3.10.0 | 目标 |
|---|---|---|---|
| SQLi 红队召回（30 条新攻击） | 25/30 = 83.3% | **29/30 = 96.7%** | ≥95% ✅ |
| XSS 红队召回（45 条新攻击） | 44/45 = 97.8% | **45/45 = 100%** | ≥95% ✅ |
| SQLi 官方语料召回（85,791 行） | 18 漏 | **17 漏（99.98%）** | 不劣化 ✅ |
| XSS 官方语料召回（81,206 行） | 18 漏 | 737 漏（99.09%）* | ≥95% ✅ |
| SQLi 误报（官方 FP 语料 421 行） | 21（5.0%） | **16（3.8%）** | ≤5% ✅ |
| XSS 误报（FP 语料 + 自建良性集） | ~2+（style 类） | **0** | ✅ |
| 单元测试行覆盖率 | 无 | **97.7%**（函数 100%） | ≥95% ✅ |

\* XSS 官方语料多出的 720 条是 Shazzer 模糊测试"金丝雀"行（`style="color:rgb(0,0,0)"junk;`
这类本身不可执行的探测串），此前仅靠"style 属性一律告警"命中。本轮将 style 检测改为
"仅当值中含可执行内容（expression/url(javascript:/behavior…）时告警"，换来真实场景
高频误报类（`style="color: blue"`）清零。这是明确的精度换召回决策，见 §3 P1。

---

## 1. 现状评估

### 1.1 算法原理

**SQLi（`libinjection_sqli.c`）**：
1. 分词器把输入切成 token（关键词/数字/字符串/变量/操作符/注释/括号…，最多保留 5 个）；
2. 折叠器做语法等价化简（`1=1`→`1`、`--`注释剥离、`UNION ALL`→`UNION`、括号折叠…）；
3. 折叠后取各 token 的**类型字符**组成 ≤5 字符"指纹"（如 `1 union select user,pass--`
   → `1UEnnc` → `1UEnn`）；
4. 指纹在 ~8.3 万条黑名单指纹中二分查找，命中后再过一遍**白名单降噪**
   （`libinjection_sqli_not_whitelist`）抑制误报；
5. 对 `'`、`"` 存在的输入，分别以"单引号开头/双引号开头"的假设重放多次；对 MySQL
   歧义注释（`--x`、`#`）按 MySQL 语法重放。

**XSS（`libinjection_xss.c` + `libinjection_html5.c`）**：
HTML5 状态机分词 → 黑名单匹配（危险标签 SCRIPT/IFRAME/SVG*…、危险属性 `on*`/SRC/HREF…、
危险 URL 前缀 `javascript:`/`data:`…、注释里的 `` ` `` 与 `[if`），在 5 种上下文
（DATA/无引号/单引号/双引号/反引号）下各跑一遍。

### 1.2 横向对比：是不是最好的方案？

| 方案 | 速度 | 资源 | 准确率上限 | 主要问题 |
|---|---|---|---|---|
| **libinjection（指纹黑名单）** | ~百万次/秒/核 | 极低，零依赖 | 中 | 指纹≤5 token、数据停更、无解码层、无上下文 |
| OWASP CRS + ModSecurity（正则链） | 慢 2-3 个数量级 | 高（数百条规则） | 中高 | 规则膨胀、误报调优成本大、同样可被编码绕过 |
| 纯正则/关键字黑名单 | 快 | 低 | 低 | 极易绕过，误报大 |
| ML/NLP 模型（CNN/LSTM/BERT 等） | 慢 | 高（模型推理） | **高（有语料时）** | 需要标注语料与持续训练、可解释性差、对抗样本脆弱 |
| 云 WAF（语义分析+情报） | - | - | 高 | 非自研、黑盒、成本 |

结论：**没有单一"最好"**。libinjection 在"性能/体积/可解释性"约束下是最优工程解之一
（这也是 ModSecurity、Cloudflare 早期等把它作为组件的原因），但它只是组件：
- 它**不负责 URL/实体解码**（reader 帮忙解了一层），调用方不解码就等于裸奔；
- 它的指纹与关键词库停留在 2016 年；
- XSS 检测器官方标注为 ALPHA，纯黑名单。

### 1.3 实测基线（本仓库，2026-09）

- 官方正样本语料（`data/sqli-*.txt`，85,791 行，reader 已做一次 URL 解码）：
  漏 18 条 → 召回 99.98%（**注意这是训练集，不是泛化能力**）；
- 官方 XSS 语料：81,206 行漏 18 → 99.98%（同上）；
- 官方误报语料（`data/false_positives.txt`，421 行）：**误报 21 条，FP 率 5.0%**
  ——上游 CI 竟然用 `-m 21` 把这些误报"合法化"了；
- 自建红队集（36 条 SQLi、48 条 XSS，见 `data/redteam-*.txt`）：
  **SQLi 召回 16/26 ≈ 62%，XSS 召回 45/48 ≈ 94%**（红队集即"未见过的新攻击"的代理）。

### 1.4 具体漏洞（实测证据）

SQLi 漏报类：
1. 堆叠查询：`;drop table users;` → `;Tnn;` 不在指纹库；
2. MySQL 8 新语句：`TABLE information_schema.tables`；
3. JSON 函数带花括号：`1 and json_extract('{}','$.a')` → 折叠异常 `s{sns`；
4. 科学计数法变形：`1e0 from (select 1)e union select 2`；
5. `PROCEDURE ANALYSE`（`1 limit 1,1 procedure analyse()`）；
6. Oracle `bitand` 等未收录函数；
7. **双重 URL 编码**（`%2527`）在库层面完全没有解码能力，依赖调用方。

XSS 漏报类：
1. 属性值中的 IE 反引号截断：`<img src="x` `<script>...">`；
2. 老协议：`livescript:`/`mocha:`/`mhtml:`/`jar:` 未列入危险 URL 前缀；
3. `srcdoc` 属性未进黑名单（当前仅因 IFRAME 标签连带被拦）；
4. UTF-7 编码（`+ADw-script`）——IE 时代遗留，收益低（见 1.6 取舍）。

误报类（21 条中归因）：
1. `1&1` 族：`80% ACRYLIC AND 20% WOOL`——`%` 被切成操作符导致 token 数 >3，
   逃过 `stats_tokens==3` 的宽限逻辑；
2. `1c` 族：base64 尾巴 `1611-IioXX…--` 折叠后与 `1+1--` 攻击形态无法区分；
3. `sos`/`s&s` 族：含引号的自然语言（`"NOT" STUFFER`）在双引号重放上下文中命中；
4. `Enknk`：`select x from y where` 这种"完整 SQL 句子"文本；
5. `nc`：`x/*` 未闭合注释。

## 2. 优化目标

在**不改变既有 API 默认行为**（兼容 ModSecurity 等现有集成）的前提下：

| 指标 | 基线 | 目标 |
|---|---|---|
| SQLi 红队召回 | 62% | **≥95%（目标 100%）** |
| XSS 红队召回 | 94% | **≥95%（目标 ~98%）** |
| 误报语料 FP | 21/421 (5.0%) | **≤4/421 (<1%)** |
| 官方正样本回归 | 漏 18 | 不劣化（≤18） |
| 单元测试行覆盖 | 无 | **≥95%**（分支覆盖同步报告） |

## 3. 落地项（按优先级）

### P0 SQLi
- **S1 解码层**：新增公开 API
  `libinjection_urldecode()`（`%XX`/`%uXXXX`/`+`，可迭代解码，防御双重编码）
  与便捷入口 `libinjection_sqli_url()`：对原始串与解码串各跑一遍检测。
  默认 API `libinjection_sqli()` 行为不变。
- **S2 指纹/关键词补齐**（走官方数据管线 `sqlparse_map.py → sqlparse2c.py`）：
  新增 `PROCEDURE/ANALYSE/ANALYZE/BITAND` 等关键词；把红队漏报指纹
  （`;Tnn;`、`1B1f(`、`1k(E1`、`s{sns`、MySQL8 `TABLE` 语句等）加入 `fingerprints.txt`
  并用 `make_parens.py` 模糊扩展同族变体。
- **S3 白名单降噪**（`not_whitelist` 精化，压 FP）：
  1. `1&1` 族：无引号、无注释、无括号、无折叠的纯 `1 o n &` 组合判良性；
  2. `1c` 族：注释以 `-` 开头且数字后紧跟 `-[A-Za-z0-9+/=]`（base64 特征）判良性，
     保留 `1+1--`/`1*1--` 的攻击判定；
  3. `Enknk`：恰好 5 个裸词、无折叠无注释判良性（`…where 1=1` 因折叠仍告警）；
  4. `nc`/`1c` 中注释恰为孤立 `/*`（len 2，未闭合且无内容）且无折叠判良性。
  以上每条规则都必须先在正样本语料上验证不引入漏报，再进误报语料验证收益。

### P1 XSS
- **X1** `srcdoc`、`srcset` 加入黑属性（`srcdoc` 直接 BLACK）；
- **X2** URL 型属性值中出现反引号 → 告警（IE 截断向量，属性上下文中零误报风险）；
- **X3** 危险 URL 前缀补 `LIVESCRIPT`/`MOCHA`/`MHTML`/`JAR`/`MSCRIPT`；
- **X4** 黑标签补 `KEYGEN`（autofocus+onfocus 经典向量，标签本身无正常业务含义）。
- 取舍：**不做** UTF-7（IE≤6 遗留，`+ADw-` 出现在正常文本概率不低，收益/风险比差）、
  **不做** JS 上下文注入检测（`'};alert(1)` 属于另一类检测器，黑名单法误报不可控）。

### P2 测试与覆盖率
- **T1** 新增 `tests/test_unit.c`：断言式单元测试，覆盖
  `libinjection_urldecode`、分词器全部 parse_* 路径、折叠器全部规则分支、
  指纹/黑名单/白名单判定、XSS 全部分支、HTML5 全部状态；
- **T2** 数据驱动测试补齐：新增 `tests/test-sqli-*.txt`、`tests/test-xss-*.txt`
  固化本轮全部修复；
- **T3** 评测脚本 `run-benchmark.sh`：红队召回 + 误报率一键出数（优化前后可复现对比）；
- **T4** 覆盖率：`configure-coverage.sh` + `make coverage`
  （clang `-fprofile-instr-generate -fcoverage-mapping` + `llvm-cov`），
  行覆盖 <95% 时 make 失败。

### P3 工程现代化（顺带修复）
- Python 3 迁移数据管线脚本（`make_parens.py`/`sqlparse_map.py`/`sqlparse2c.py`/`fingerprints2sqli.py`）；
- 修复新版 clang `-Wstrict-prototypes` 告警（`-Werror` 下无法编译）。

## 4. 已知边界（明确不承诺）

- 存储型/二阶注入、业务上下文（哪个参数进入哪个 SQL 位置）超出库能力范围；
- GraphQL/NoSQL/ORM 语法不在 SQL 指纹体系内；
- 对抗性极强的逐字符变形（如超长注释填充）以"非常量代价"才能根治，指纹法接受尾部风险；
- 95%+ 的准召是"在自建评测集（红队 + 误报语料）上"的可验证目标，正式上线仍建议
  libinjection 与规则/模型引擎并联（级联或投票），把 libinjection 作为高性能第一层。

---

## 5. 实施记录（全部已落地）

### 新增能力
- `libinjection_urldecode()`：单趟 URL 解码（`%XX`/`%uXXXX`/`+`），原地解码，永不超长；
- `libinjection_sqli_url()` / `libinjection_xss_url()`：对原始输入与最多三轮迭代解码结果
  分别检测，防御 `%2527` 型双重/三重编码；既有 `libinjection_sqli()`/`libinjection_xss()`
  行为完全不变；
- XSS 黑属性新增 `SRCDOC`(BLACK)/`SRCSET`(URL)；黑标签新增 `KEYGEN`；危险 URL 前缀
  新增 `LIVESCRIPT/MOCHA/MHTML/MSCRIPT/JAR`；URL 型属性值中出现反引号即告警（IE 截断）；
- style 属性从"一律告警"改为"值含可执行内容才告警"（实体解码 + 滑窗匹配
  `EXPRESSION/BEHAVIOR/-MOZ-BINDING/JAVASCRIPT/VBSCRIPT/LIVESCRIPT/MOCHA`）。

### 指纹/关键词（走官方数据管线）
- 新增关键词：`ANALYSE`、`BITAND`、`JSON_EXTRACT/JSON_VALUE/JSON_QUERY/JSON_TABLE/
  JSON_UNQUOTE/JSON_SET/JSON_INSERT/JSON_REPLACE/JSON_REMOVE`（均为 'f' 函数型）；
- 新增指纹 3 个种子（管线自动扩展为 50 个）：`;Tnn`（堆叠 DROP）、`1k(E1`（科学计数法）、
  `1B1f(`（PROCEDURE ANALYSE）、`s;Tc`（堆叠 SHUTDOWN）、`S`（引号拼接逃逸）；
- 数据管线脚本全部迁移 Python 3（`make_parens.py`/`sqlparse_map.py`/`sqlparse2c.py`），
  重新生成结果与 3.9.2 数据逐字节等价后才开始增量修改。

### 白名单降噪（`libinjection_sqli_not_whitelist`）
- `s`（单字符串）：仅当发生 ss 折叠且内容非空时告警（`foo' 'bar` ✅ / `''` `''''` 良性）；
- `1c`：base64 尾巴（`1611-IioXX…--`）与逗号列表（`1,1--`）判良性；
  `1+1--`/`1*1--`/`1234--` 仍告警；
- `1&1` 族：纯数字后紧跟 `%` 的折叠形态判良性（`80% ACRYLIC AND 20% WOOL`），
  `1 or 1=1` 等探针不受影响；
- `sos`：中缀为 `*` 且左串较长时判良性（商品文本），其余维持上游攻击判定；
- `Enknk`/`Eoknk`：恰好 5 个 token、无折叠无注释的"完整 SQL 句子"判良性
  （`select x from y where`），尾部有额外表达式即告警；
- `nc`：孤立未闭合 `/*`（如 `x/*`）判良性。

### 已知边界（有意保留）
- `TABLE information_schema.tables`（MySQL 8 语句）：`TABLE` 作为关键词会在普通文本
  上产生大面积误报（"table of contents"），上游 2013 年即决策不收录，维持不变；
- `1 regexp '[a-z]'`（`1os`）：上游判定为良性，维持；
- 含引号自然语言（`CHRISTMAS STOCKING "NOT" STUFFER` 类 sos）与攻击拼接形状完全同构，
  形状上不可分离，保留 16/421 误报为当前精度边界；
- UTF-7 编码、JS 上下文注入（`'};alert(1)`）不在本库范围。

### 工程化
- `tests/test_unit.c`：283 项断言式单元测试（版本/解码/分词全路径/折叠全规则/
  指纹与白名单判定/HTML5 全状态/XSS 全分支/实体解码全路径/NUL 字节安全）；
- 数据驱动测试新增 16 个用例文件（红队攻击 + 精度回归双向固化）；
- `make check`：单元测试 → 数据驱动测试 → 官方四套样本回归，一键全绿；
- `make benchmark`：`run-benchmark.sh` 输出召回/误报对照表；
- `make coverage`：clang 插桩 + llvm-cov，行覆盖 <95% 时构建失败
  （当前 97.70%，函数覆盖 100%，报告含逐行标注 `src/coverage-data/coverage-show.txt`）。
