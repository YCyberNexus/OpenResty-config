# WAF 规则配置指南（给运维团队）

部署完成后，运维团队的日常工作就是**配规则**——规则全部集中在一个文件：

```
conf/waf_rules.lua
```

> **改这一个文件就够了。** `lua/waf/*.lua` 是规则引擎，**不要动**；`conf/nginx.conf` 属于网络/上游配置（端口、`proxy_pass`、证书），改动影响面更大、需更谨慎。本指南只讲 `conf/waf_rules.lua`。

**先进项目目录再操作**——本文所有相对路径（`conf/...`、`scripts/...`、`make ...`）都相对项目根目录：

```bash
cd /opt/openresty-waf        # 服务器上的部署目录（开发机上则是仓库根目录）
```

每次改完，走这套三层校验（缺一不可）：

```bash
make lint        # ① 配置体检：引用一致性 / 必填 / method 大小写 / 黑白冲突…（抓 -t 抓不到的坑）
openresty -p /opt/openresty-waf/ -c conf/nginx.conf -t   # ② 语法 + 能否加载
sudo systemctl reload openresty-waf                       # ③ 通过才热加载生效
bash scripts/smoke.sh                                     # ④ 真实请求验证
```

> 🚑 **红线（最重要的一条）**：只要 `make lint` 报 **ERROR** 或 `-t` 不通过，**绝对不要 reload，更不要 `systemctl restart` / 重启机器**。此刻现网仍在正常服务——回去按报错改好、重新校验通过为止。
>
> 原因是 `waf_rules.lua` 在进程启动时由 `init_by_lua` 加载，**配置写错会让整个 WAF 起不来（fail-closed，不是降级放行）**。`reload` 时 nginx 会先测新配置、测不过就拒绝 reload 并让旧进程继续服务，所以坏配置不会立刻中断现网；真正的灾难是**进程重启**（机器重启 / `restart` / 崩溃拉起）时撞上坏配置——那时 WAF 直接拒绝启动。所以「先校验、再 reload」是硬要求。

> 若服务器上 `make` / `luajit` / `openresty` 不在 PATH：
> - `make lint` 的等价直接命令：`/usr/local/openresty/luajit/bin/luajit scripts/check_rules.lua`
> - 配置校验：`/usr/local/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx.conf -t`
> - `systemctl` 操作一般需要 `sudo`；reload 失败看原因：`tail -n 50 logs/error.log` 或 `journalctl -u openresty-waf -e`

---

## 1. 配置文件长什么样

`conf/waf_rules.lua` 返回一个 Lua 表，只有三个部分：

```lua
return {
  whitelist = { ... },   -- 白名单：哪些接口允许进（未命中一律拒）
  blacklist = { ... },   -- 黑名单：先于白名单，命中即拒
  schemas   = { ... },   -- body 校验器：限制请求体的结构与内容
}
```

**一次请求的判定顺序**（改任何一处前，先理解这个流程）：

```
请求 ──> ① 黑名单匹配? ──命中──> 403 (reason=blacklist)
            │未命中
            ▼
         ② 白名单匹配? ──未命中──> 403 (reason=not_in_whitelist)   ← 默认拒绝
            │命中某条规则
            ▼
         ③ 该规则有 body=? ──无──> 放行 200
            │有
            ▼
         body JSON 校验 ──不过──> 400/422 ──过──> 放行 200
```

---

## 2. whitelist —— 白名单（决定哪些接口能进）

数组，每条是一个规则表。**未命中白名单的请求一律 403**，这是「默认拒绝」。

```lua
whitelist = {
  { methods = { "POST" }, path = "/v1/chat/completions", body = "chat" },
  { methods = { "GET" },  path = "/v1/models" },
},
```

| 字段 | 必填 | 含义 |
|---|---|---|
| `methods` | 否 | 允许的 HTTP 方法数组，如 `{ "POST" }`。**必须大写**（代码大小写敏感）。**省略 = 不限方法** |
| `path` | path / pattern 二选一 | **精确**匹配，整条路径全等才命中（`/v1/models` 只匹配 `/v1/models`） |
| `pattern` | path / pattern 二选一 | **正则**匹配（PCRE），用于一批路径。写法见第 6 节 |
| `body` | 否 | 指向 `schemas` 里某个校验器的名字；命中后对请求体做该校验。无此字段则不校验 body |

要点：
- `path` 和 `pattern` **二选一**。两个都写 → **`path` 优先、`pattern` 被忽略**（`make lint` 警告）。
- 两个都不写 → 该规则**永远不命中**，等于没配（`make lint` 报 error）。
- `body` 只对**有请求体的方法**（POST/PUT/PATCH）有意义。给 GET 配 `body` 会让该 GET 请求全部 400（GET 不读 body，`body` 为 `nil` 被判非对象）——`make lint` 现在会报 error。

---

## 3. blacklist —— 黑名单（先于白名单，命中即拒）

写法和白名单一样用 `path` / `pattern` / `methods`，但**没有 `body`**（黑名单只看 URL）。命中即返回 403。

```lua
blacklist = {
  { pattern = "^/admin" },     -- 拦所有以 /admin 开头的路径
  { pattern = "^/v1/admin" },  -- 拦 OpenClaw 控制面/管理端点
},
```

要点：
- 黑名单**先于**白名单判。即使某路径在白名单里，只要也命中黑名单就拒——用它兜底拦管理端点、危险路径。
- `^/admin` 是**前缀正则**（没有 `$`），会匹配 `/admin`、`/admin/x`，**也会匹配 `/admin-console`、`/administrator`**。只想精确拦 `/admin` 用 `path = "/admin"` 或 `pattern = "^/admin$"`。
- ⚠️ 黑名单的 `methods` 若写错（小写、或漏花括号写成标量 `"GET"`），这条拦截会**静默失效形成绕过**。`make lint` 现在会对此报 error。

---

## 4. schemas —— body 校验器（限制请求体）

一个 map：`名字 → 校验规则`。白名单规则用 `body = "名字"` 来引用它。

```lua
schemas = {
  chat = {
    models             = { "gpt-4o", "gpt-4o-mini", "claude-opus-4-8" },
    max_messages       = 50,
    max_content_length = 8000,
    max_total_length   = 32000,
    allowed_roles      = { "system", "user", "assistant" },
    allowed_fields     = { "model", "messages", "stream", "temperature",
                           "top_p", "max_tokens", "n", "stop" },
  },
},
```

| 字段 | 必填 | 含义与**配错的后果** |
|---|---|---|
| `models` | **是，非空** | 允许的 `model` 取值白名单。空或缺失 → 该接口所有请求 422 |
| `allowed_fields` | **是，非空** | 请求体顶层允许出现的字段（`additionalProperties:false`）。**必须含 `model` 和 `messages`**；漏了哪个字段，带该字段的正常请求就被当「未知字段」拒 400 |
| `allowed_roles` | **是，非空** | 每条 message 的 `role` 白名单。**通常要含 `user`**，否则正常对话全 422 |
| `max_messages` | **是，正整数** | `messages` 条数上限 |
| `max_content_length` | **是，正整数** | 单条 message `content` 字节数上限 |
| `max_total_length` | **是，正整数** | 所有 message `content` 累计字节数上限 |

> ⚠️ 三个 `max_*` 必须是**大于 0 的整数**：漏配或写成非数字 → 正常请求（能过前面校验的）走到长度比较处 500；配成 0 或负数 → 该接口正常请求被全拒（422）。`make lint` 两种都会报 error。

**校验顺序**（严格按代码，便于对照日志里的 `field`）：
1. 请求体必须是 JSON 对象（否则 400）；
2. 顶层不能有 `allowed_fields` 之外的字段（否则 400）；
3. 必须有 `messages` 和 `model`（否则 400）；
4. `model` 在 `models` 白名单内（否则 422）；
5. `messages` 是非空数组（否则 400）、条数 ≤ `max_messages`（否则 422）；
6. **逐条** message 依次：`role` 在 `allowed_roles` 内（否则 422）→ 若 `role` 是 `system` 则**必须是第一条**（否则 422）→ `content` 是字符串（否则 400）→ `content` 字节数 ≤ `max_content_length`（否则 422）；
7. 累计 `content` 字节数 ≤ `max_total_length`（否则 422）。

> `system` 必须首位 ⇒ 最多一条 system（防伪造 system 越权注入）。当前限制：长度按**字节**算（中文/emoji 偏大）；`content` 只接受字符串，多模态数组一律拒——这是 P3-4 / P3-5 的后续项。

**可整段复制的最小合法 schema 模板**（新建 schema 时先抄它，再改值——六个字段一个都不能少）：

```lua
my_schema = {
  models             = { "gpt-4o" },                          -- 必填，非空；按需加 model
  allowed_roles      = { "system", "user", "assistant" },     -- 必填，非空；通常要含 "user"
  allowed_fields     = { "model", "messages" },               -- 必填；必须含 model 和 messages
  max_messages       = 50,                                    -- 必填，正整数（不要加引号）
  max_content_length = 8000,                                  -- 必填，正整数
  max_total_length   = 32000,                                 -- 必填，正整数
},
```

---

## 5. 返回码总表（看日志定位用）

被拒只回 `{ "error": "<原因>", "field": "<字段>", "request_id": "..." }`，不回显规则细节。日志在 `logs/error.log`，每条带 `waf action=... reason=... field=...`。

| 码 | reason | 触发 |
|---|---|---|
| 200 | — | 放行 |
| 403 | `blacklist` | 命中黑名单 |
| 403 | `not_in_whitelist` | 未命中白名单（默认拒绝） |
| 415 | `unsupported_media_type` | POST/PUT/PATCH 但 `Content-Type` **不包含** `application/json` 子串（子串匹配、区分大小写） |
| 400 | `invalid_json` | 请求体不是合法 JSON |
| 400 | `body`（code=schema） | body **结构**错：非对象 / 未知字段 / 缺 model 或 messages / messages 非数组或空 / message 非对象 / content 非字符串 |
| 422 | `body`（code=policy） | body **策略**错：model 不允许 / 条数超限 / 长度超限 / **role 非法** / **system 不在首位** |
| 500 | `misconfigured` | **配置错**：白名单 `body=` 指向了不存在的 schema |

> 看到 **500**（`misconfigured` 或正常请求 500）几乎都是 `waf_rules.lua` 配错——回第 4 节核对 schema 名字与 `max_*`，用 `make lint` 一键定位。

---

## 6. 改配置的 Lua 语法最小须知（防手滑）

`waf_rules.lua` 是 Lua 表，不懂 Lua 也能照葫芦画瓢，但这几条手滑点最致命：

- **字符串用双引号**：`"POST"`、`"/v1/models"`。
- **数字直接写、不要加引号**：`max_messages = 50` ✅；`max_messages = "50"` ❌（变成字符串，运行期 500，而且 `-t` 检查不出来）。
- **表项之间都要逗号**，**字符串列表也一样**：
  ```lua
  models = { "gpt-4o", "gpt-4o-mini" }   -- ✅ 元素间有逗号
  models = { "gpt-4o" "gpt-4o-mini" }    -- ❌ 漏逗号，加载报错
  ```
- **Lua 表一律用花括号 `{ }`，不是方括号 `[ ]`**（有 JSON/数组背景的人极易写错）。
- **注释用 `--`**（行注释），块注释用 `--[[ ... ]]`。
- **正则里有反斜杠时，用长字符串 `[[ ... ]]` 写**：

  ```lua
  -- 判断标准：正则里只要出现反斜杠 \（如 \d \w \. \s）就必须用 [[ ]]；
  -- 没有反斜杠时双引号、[[ ]] 都行——统一都用 [[ ]] 最省心，不会错。
  { pattern = "^/v1/files/\d+$" }     -- ❌ Lua 双引号里 \d 非法转义，加载直接报错
  { pattern = [[^/v1/files/\d+$]] }   -- ✅ 长字符串原样保留反斜杠
  ```
  注意：`[[ ]]` 里**不要再写 `\` 转义**，按 PCRE 原样写即可；若正则本身含 `]]`（如字符类），改用 `[==[ ... ]==]`。正则锚点 `^` 开头、`$` 结尾；避免会回溯爆炸的写法（如 `(a+)+`）。

---

## 7. 常见配置任务 Cookbook（照抄改）

**① 放行一个新接口（无 body 校验）** —— 往 `whitelist` 加一条：
```lua
{ methods = { "GET" }, path = "/v1/usage" },
```

**② 放行一个新的非 chat 接口** —— **当前先只配 URL 白名单、不挂 body**：
```lua
{ methods = { "POST" }, path = "/v1/embeddings" },
```
> 为什么不挂 body：现在的 `body_validator` 是按 Chat Completions 形态写死的（强制要有 `messages`、校验 `role`）。给 embeddings（请求体是 `{model, input}`、没有 messages）挂上任何 schema，会让它**所有请求被全拒 400**（`input` 是未知字段 / 缺 `messages`）。非 chat 接口要做请求体校验，需引擎侧扩展（后续项），不能只靠改配置。拿不准就先只放 URL。

**③ 给一个 chat 形态的新接口加 body 校验** —— 先在 `schemas` 抄第 4 节模板建校验器，再在 `whitelist` 用 `body=` 引用：
```lua
-- schemas 里加（抄模板改值）：
chat_v2 = {
  models = { "gpt-4o", "claude-opus-4-8" },
  allowed_roles = { "system", "user", "assistant" },
  allowed_fields = { "model", "messages", "stream" },
  max_messages = 50, max_content_length = 8000, max_total_length = 32000,
},
-- whitelist 里加（注意是 POST）：
{ methods = { "POST" }, path = "/v2/chat/completions", body = "chat_v2" },
```

**④ 新增一个允许的 model** —— 在对应 schema 的 `models` 里加（注意逗号）：
```lua
models = { "gpt-4o", "gpt-4o-mini", "claude-opus-4-8", "claude-sonnet-4-6" },
```

**⑤ 调整长度 / 条数上限** —— 改 schema 里的 `max_*` 数字（保持是正整数、不加引号）。

**⑥ 用正则放行一批路径**：
```lua
{ methods = { "GET" }, pattern = [[^/v1/models/[\w.-]+$]] },
```

**⑦ 拉黑一个路径 / 前缀** —— 往 `blacklist` 加：
```lua
{ pattern = "^/internal" },
```

**⑧ 临时下线一个接口** —— 把那条白名单**注释掉**（下线后该接口自动落入默认拒绝 403）：
```lua
-- { methods = { "GET" }, path = "/v1/models" },
```
> ⚠️ 若被下线的规则**占多行**（如换行写的 `allowed_fields`、或一条写成多行的规则），**每一行行首都要加 `--`**，或更稳妥地用块注释 `--[[ ... ]]` 把整条包起来：
> ```lua
> --[[
> { methods = { "POST" }, path = "/v2/chat/completions",
>   body = "chat_v2" },
> --]]
> ```
> 只注释第一行、剩下几行变成裸语句，会让整个文件语法错、reload 失败。

---

## 8. 改完怎么确保没配错（三层校验）

三个工具各管一段，**盲区互补，建议都跑**：

| 命令 | 抓什么 | 抓不到什么 |
|---|---|---|
| `make lint`（= `luajit scripts/check_rules.lua`） | Lua 语法、**body 引用的 schema 是否存在**、`allowed_fields` 是否含 model/messages、`max_*` 是否为正整数、`allowed_roles` 是否含 user、**method 是否大写合法**、**body 是否误配给 GET**、**黑白名单 path 冲突**、**同 path 规则短路 body 校验** | 规则是否「符合业务意图」 |
| `openresty ... -t` | nginx 语法、`init_by_lua` 能否加载（`require` 成功） | **不查 body 引用一致性**、不实际发请求、不感知 method 大小写/HTTP 语义 |
| `bash scripts/smoke.sh` | 端到端：真实请求的放行/拦截是否符合预期 | 只覆盖脚本里写的用例 |

`make lint` 的核心价值：`openresty -t` 启动时**不会**真的判一条请求，所以「`body="chat"` 但 schemas 里其实叫 `chatt`」「method 写成小写 `"post"`」这类错 `-t` 发现不了——要等真实请求打进来才 500/全拒。`make lint` 把这些在改完当场抓出来，例如：

```
✗ ERROR  whitelist[1]  body 引用了不存在的 schema："chatt"；该接口所有请求会 500（misconfigured）
✗ ERROR  whitelist[1]  method "post" 非法：必须大写且为标准 HTTP 方法，如 "POST"（代码大小写敏感，小写永不命中）
```

**标准变更流程**（先 `cd /opt/openresty-waf`）：

```bash
ls -l conf/waf_rules.lua.bak.* 2>/dev/null                        # 看下已有备份
cp conf/waf_rules.lua "conf/waf_rules.lua.bak.$(date +%Y%m%d%H%M)" # ① 改前备份（bash 下执行）
ls -l conf/waf_rules.lua.bak.*                                     #    确认备份文件名/大小正常
vi /opt/openresty-waf/conf/waf_rules.lua                           # ② 改（用绝对路径，别改错文件）
make lint                                                          # ③ 体检——有 ERROR 就停下改，别往下走
openresty -p /opt/openresty-waf/ -c conf/nginx.conf -t             # ④ 语法 + 加载校验
sudo systemctl reload openresty-waf                                # ⑤ 前两步都过，才热加载
bash scripts/smoke.sh                                              # ⑥ 实测
```

> 备份会越积越多，定期清理旧的（如只留最近几个）。

**回滚**（出问题时，同样要「先校验再 reload」，别盲拷）：
```bash
ls -lt conf/waf_rules.lua.bak.*                                   # ① 按时间挑最新的好备份
cp conf/waf_rules.lua.bak.<时间戳> conf/waf_rules.lua             # ② 拷回
make lint && openresty -p /opt/openresty-waf/ -c conf/nginx.conf -t   # ③ 先确认备份本身是好的
sudo systemctl reload openresty-waf                              # ④ 通过才 reload
bash scripts/smoke.sh                                            # ⑤ 实测
```

---

## 9. 高频踩坑速查（都基于代码真实行为）

| 现象 | 原因 | 修 |
|---|---|---|
| 某接口所有请求 **500 misconfigured** | 白名单 `body="x"` 但 `schemas` 没有 `x`（拼写/漏定义） | 名字对齐；`make lint` 当场抓 |
| 正常请求 500 | schema 漏配 `max_*`，或写成 `"50"`（带引号的字符串） | 三个 `max_*` 都填**不带引号的正整数** |
| 正常请求全 **400 unknown field** | `allowed_fields` 漏了请求里用到的字段（尤其 `model`/`messages`） | 补进 `allowed_fields` |
| 正常对话全 **422** | `allowed_roles` 漏了 `user`，或某 `model` 不在 `models`，或 `max_*` 配成 0/负数 | 补 `user` / 补 model / `max_*` 改正整数 |
| 规则**写了却不生效** | `path` 和 `pattern` 都写了（path 优先），或两个都没写，或 method 写成小写 | 二选一；method 大写；`make lint` 提示 |
| 白名单接口被 **403 全拒** | 该 path 同时命中黑名单（黑名单先判），或 method 配错 | 查黑名单遮蔽 / 改 method；`make lint` 抓 path 冲突 |
| 黑名单**没拦住** | 黑名单 method 写成小写或标量，规则失效 | method 用大写数组；`make lint` 抓 |
| body 校验**被绕过** | 同一 path 配了多条规则，靠前那条没挂 body 短路了校验 | 合并规则；`make lint` 报短路 error |
| 改完 reload 报错、没生效 | `waf_rules.lua` 语法错（少逗号、`"\d"` 转义、方括号） | 先 `make lint` / `-t`，按报错改；现网不受影响（旧进程还在）→ **不要 restart** |

---

## 10. 职责与变更评审

- **运维方**维护 `waf_rules.lua`（配规则）；**应用方**提供接口契约（哪些 path/method、请求体字段与数值上限）。当前 schema 里的数值（`max_*`、`models`）是占位，要按应用方给的接口契约据实收紧——对应方案的搁置项（接口契约与数值上限）。
- 建议每次规则变更：**git 留痕**（谁、改了什么、为什么）+ 走评审/审批后再 reload。谁有权批准「放行一个新接口 / 新 model」，对应方案待澄清的「路由收口审批责任」，上线前应与相关方拍板。
- 规则是「**先黑后白 + 默认拒绝**」：新接口不主动加白名单就是默认拒。这是有意的安全姿态——**宁可漏放，不可错放**。
