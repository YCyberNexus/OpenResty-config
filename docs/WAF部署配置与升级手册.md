# WAF 部署、配置、升级与验收手册

## 1. 文档目的

本文是本仓库唯一的 WAF 运维操作手册，覆盖：

- 双 WAF 当前架构和安全边界；
- 两个黄区目标使用相同 path、不同请求及响应契约的配置；
- `waf_rules.lua` 请求和响应 schema 配置；
- 全新部署；
- 已运行旧版本的完整升级；
- 配置检查、验收、审计、日常变更和回滚。

以下文件是依据材料，不在本文中重复维护：

- [数据安全策略图（整改目标）](architecture/数据安全策略图-整改目标.png)：公司级安全目标基线；
- [绿蓝黄数据链路白名单台账](绿蓝黄数据链路白名单台账.md)：业务链路、审批字段和上线门禁；
- [知识库接口文档](知识库接口文档.md)：用户提供的接口契约副本。

架构图描述整改目标，不代表所有控制已在现网完成。具体 IP、端口、Host、四层 ACL、接口契约、负责人和审批状态必须以现场记录为准。

## 2. 当前架构与责任边界

```text
蓝区调用方 → 蓝 WAF → HTTP → 黄 WAF → 黄区固定目标 A/B
```

当前已确认蓝、黄 WAF 之间依靠四层网络策略限制登记的源、目标 IP 和端口，本仓库当前版本不配置 mTLS。

七层 WAF 负责：

- 精确 `host + method + path` 白名单；
- 默认拒绝 query string；
- JSON 请求体大小、字段、类型和取值范围校验；
- 按 Host 和响应状态码选择响应 schema；
- 在响应正文返回前检查大小、媒体类型、编码、JSON 和字段；
- 请求、响应摘要及处置结果审计。

七层 WAF 不替代：

- 防火墙和四层来源限制；
- EDR、DLP、ODCP、AD、Jumpserver、VDI；
- 业务身份认证和权限系统；
- K3 数据识别、业务脱敏和文件外发审批；
- 日志集中转储及防篡改平台。

必须保持以下约束：

1. 蓝区调用方不得绕过蓝 WAF 或黄 WAF 直连目标服务；
2. 黄 WAF 只代理配置中固定登记的目标，不接受请求动态指定 URL、IP、端口或 upstream；
3. 黄区目标服务只接受黄 WAF 等已登记来源；
4. 蓝、黄 WAF 使用同一份活动规则文件；
5. 未登记的 Host、接口、字段、状态码或响应结构默认拒绝。

## 3. 当前能力和限制

| 项目 | 当前限制 |
|---|---|
| 请求类型 | 只支持 JSON 请求或无正文请求 |
| 请求体全局上限 | 最大 16384 字节 |
| 响应类型 | 只支持 `application/json` |
| 响应体全局上限 | 最大 1048576 字节 |
| query string | 全部拒绝 |
| 压缩响应 | 拒绝 gzip 等非 identity 编码 |
| 流式响应 | 不支持 SSE 或持续流式业务响应 |
| 文件响应 | 不支持文件下载或二进制响应 |
| 响应处理 | 完整缓冲、校验、重新编码后返回 |

响应缓冲会占用内存。上线前应结合最大响应体、并发量和 QPS 做容量评估，不得只按单请求上限判断资源是否足够。

## 4. 上线前必须收齐的信息

两个服务分别提供：

- 正式业务 Host；
- 目标 IP、端口和目标服务要求的 Host；
- method、精确 path、Content-Type；
- 请求字段、类型、必填项、长度和数值限制；
- 所有成功及错误 HTTP 状态码；
- 每个状态码对应的完整响应字段；
- 请求体和每种响应体的最大字节数；
- 敏感字段、允许跨区返回的内容及数据分级审批；
- QPS、并发、超时、owner、工单、有效期和回滚窗口；
- 四层 ACL、DNS 及旁路拒绝验证记录。

第二个同路径服务的真实请求、响应、状态码或大小限制未收齐时，不得用仓库演示字段直接生产放行。

## 5. 同路径双目标如何区分

规则唯一键是：

```text
host + method + path
```

示例：

```text
knowledge-a.waf.internal + POST + /ai/knowledge/search
  → 请求 schema A → 目标 A → 响应 schema A

knowledge-b.waf.internal + POST + /ai/knowledge/search
  → 请求 schema B → 目标 B → 响应 schema B
```

如果两个请求使用相同 Host、method 和 path，WAF 无法区分目标。必须提供两个不同的业务 Host，或另行设计受控入口；不能把完整 URL 填入 `path`。

以两个后端地址为例：

| 原地址部分 | 配置位置 |
|---|---|
| `192.168.14.249:6789` | 黄 WAF 目标 A 的 upstream IP/端口 |
| `192.168.14.250:6789` | 黄 WAF 目标 B 的 upstream IP/端口 |
| `/ai/knowledge/search` | 两条规则各自的 `path` |
| 业务 Host A/B | 规则 `host` 及蓝、黄模板的 `server_name` |

正式 DNS 应将 Host A、Host B 都解析到蓝 WAF。蓝 WAF 保留已匹配的 Host 转发给黄 WAF，黄 WAF 再通过两个静态虚拟主机分别选择固定目标 A、B。Host 是受限路由键，不是身份认证凭证。

## 6. 仓库和服务器文件

### 6.1 主要仓库文件

| 文件 | 用途 |
|---|---|
| `conf/waf_rules.lua` | 生产活动规则；仓库默认空白名单 |
| `conf/waf_rules_same_path_example.lua` | 同路径、不同 Host 和契约的演示 |
| `conf/waf_rules_knowledge_example.lua` | 知识库接口请求及响应示例 |
| `conf/nginx-blue.conf.template` | 蓝 WAF 生产模板 |
| `conf/nginx-yellow.conf.template` | 黄 WAF 双固定目标模板 |
| `conf/waf-public-location.conf` | 请求校验和响应捕获入口 |
| `conf/waf-internal-proxy-common.conf` | internal 固定 upstream 代理配置 |
| `lua/waf/*.lua` | 匹配、schema、请求及响应处理代码 |
| `scripts/check_rules.lua` | 规则静态检查 |
| `scripts/server-setup.sh` | 目录权限和节点配置检查 |
| `deploy/openresty-waf@.service` | systemd 模板单元 |

### 6.2 服务器生效文件

```text
/opt/openresty-waf/conf/nginx-blue.conf
/opt/openresty-waf/conf/nginx-yellow.conf
/opt/openresty-waf/conf/waf_rules.lua
/opt/openresty-waf/lua/waf/*.lua
/etc/systemd/system/openresty-waf@.service
```

systemd 加载渲染后的 `.conf`，不会加载 `.template`。蓝、黄服务器上的 `waf_rules.lua` 和 Lua 代码必须来自同一完整版本。

## 7. 规则配置

### 7.1 顶层结构

```lua
return {
  max_request_body_bytes = 16384,
  max_response_body_bytes = 1048576,
  whitelist = {},
  schemas = {},
}
```

| 字段 | 要求 |
|---|---|
| `max_request_body_bytes` | 大于 0，最大 16384 |
| `max_response_body_bytes` | 大于 0，最大 1048576 |
| `whitelist` | 精确接口白名单数组 |
| `schemas` | 请求和响应共用的 schema 字典 |

仓库活动文件默认 `whitelist = {}`。空白名单只允许配置检查通过，但会输出 warning，并拒绝全部业务接口。

### 7.2 白名单规则

```lua
{
  id = "SERVICE-A-SEARCH",
  host = "knowledge-a.waf.internal",
  methods = { "POST" },
  path = "/ai/knowledge/search",
  request_schema = "service_a_request",
  responses = {
    [200] = { schema = "service_a_success_response", max_body_bytes = 65536 },
    [422] = { schema = "service_a_error_response", max_body_bytes = 16384 },
  },
}
```

| 字段 | 要求 |
|---|---|
| `id` | 稳定、唯一、非空的台账规则编号 |
| `host` | 小写精确 Host，不含端口、通配符、路径或正则 |
| `methods` | 非空大写 HTTP 方法数组 |
| `path` | 以 `/` 开头，不含 query 或 fragment 的精确路径 |
| `request_schema` | 有请求体时必填；不填则该接口禁止正文 |
| `responses` | 必填；按 HTTP 状态码登记 schema 和最大响应字节数 |

`/__waf_upstream` 是内部保留前缀，不得登记为业务 path。

### 7.3 两个 Host 使用不同契约

```lua
whitelist = {
  {
    id = "SERVICE-A-SEARCH",
    host = "knowledge-a.waf.internal",
    methods = { "POST" },
    path = "/ai/knowledge/search",
    request_schema = "service_a_request",
    responses = {
      [200] = { schema = "service_a_response", max_body_bytes = 65536 },
    },
  },
  {
    id = "SERVICE-B-SEARCH",
    host = "knowledge-b.waf.internal",
    methods = { "POST" },
    path = "/ai/knowledge/search",
    request_schema = "service_b_request",
    responses = {
      [200] = { schema = "service_b_response", max_body_bytes = 65536 },
    },
  },
}
```

除非两个接口的字段、状态码和大小限制完全一致，否则不要复用请求或响应 schema。

### 7.4 请求 schema 示例

```lua
service_a_request = {
  type = "object",
  additional_properties = false,
  required = { "query" },
  properties = {
    query = {
      type = "string",
      min_length = 1,
      max_length = 4000,
      max_bytes = 16000,
      non_blank = true,
    },
    top_k = {
      type = "integer",
      minimum = 1,
      maximum = 50,
    },
  },
}
```

WAF 不会给可选字段补默认值。`additional_properties=false` 会拒绝未登记字段。

### 7.5 响应 schema 示例

```lua
service_a_error_response = {
  type = "object",
  additional_properties = false,
  required = { "detail" },
  properties = {
    detail = {
      type = "string",
      min_length = 1,
      max_length = 1000,
    },
  },
}
```

成功和错误响应应按实际状态码分别建模。接口文档未明确的字段不得自行推断为生产契约；例如知识库 `metadata` 的完整字段范围仍需业务方确认。

### 7.6 支持的 schema 关键字

- 类型：`object`、`array`、`string`、`integer`、`number`、`boolean`、`null`；
- 对象：`required`、`properties`、`additional_properties=false`、`max_properties`；
- 数组：`items`、`min_items`、`max_items`；
- 字符串：`min_length`、`max_length`、`max_bytes`、`non_blank`、`trimmed`、`prefix`、`format`；
- 数值：`minimum`、`maximum`；
- 通用：`enum`。

object 必须显式配置 `properties` 和 `additional_properties=false`。未知配置关键字、缺失 schema 引用或重复路由会导致检查失败。

### 7.7 规则检查

```bash
cd /opt/openresty-waf
/data/openresty/luajit/bin/luajit scripts/check_rules.lua conf/waf_rules.lua
```

上线规则必须满足：

- `0 error`；
- 不出现空白名单 warning；
- 输出中的 Host、method、path、请求 schema 和响应状态码与审批材料一致；
- 蓝、黄两端文件 SHA-256 一致。

```bash
sha256sum /opt/openresty-waf/conf/waf_rules.lua
```

## 8. Nginx 节点配置

### 8.1 黄 WAF

```bash
cd /opt/openresty-waf
sudo cp conf/nginx-yellow.conf.template conf/nginx-yellow.conf
sudo vi conf/nginx-yellow.conf
```

替换：

```text
__YELLOW_WAF_LISTEN_IP__
__YELLOW_WAF_PORT__
__WAF_SERVICE_HOST_A__
__WAF_SERVICE_HOST_B__
__PROTECTED_SERVICE_A_IP__
__PROTECTED_SERVICE_A_PORT__
__PROTECTED_SERVICE_A_HOST__
__PROTECTED_SERVICE_B_IP__
__PROTECTED_SERVICE_B_PORT__
__PROTECTED_SERVICE_B_HOST__
```

黄 WAF 固定映射：

```text
Host A → protected_backend_a
Host B → protected_backend_b
```

`__PROTECTED_SERVICE_A_HOST__` 和 `__PROTECTED_SERVICE_B_HOST__` 应填写后端实际要求的 Host。只有业务方确认后端接受 IP Host 时才能填写 IP。

### 8.2 蓝 WAF

```bash
cd /opt/openresty-waf
sudo cp conf/nginx-blue.conf.template conf/nginx-blue.conf
sudo vi conf/nginx-blue.conf
```

替换：

```text
__BLUE_WAF_LISTEN_IP__
__BLUE_WAF_LISTEN_PORT__
__WAF_SERVICE_HOST_A__
__WAF_SERVICE_HOST_B__
__YELLOW_WAF_IP__
__YELLOW_WAF_PORT__
```

两个 `__WAF_SERVICE_HOST_*__` 必须与规则 `host` 完全一致。蓝 WAF 只连接一个已登记的黄 WAF 地址，并保持业务 Host 供黄 WAF 静态选路。

### 8.3 占位符检查

```bash
grep -En '__[A-Z0-9_]+__' /opt/openresty-waf/conf/nginx-yellow.conf
grep -En '__[A-Z0-9_]+__' /opt/openresty-waf/conf/nginx-blue.conf
```

对应节点的命令必须无输出。不要直接复用旧版渲染配置；应以当前版本模板重新生成并人工迁移现场值。

## 9. 生成和交付安装包

在仓库根目录执行：

```bash
bash scripts/package.sh /tmp/openresty-waf-release.tgz
shasum -a 256 /tmp/openresty-waf-release.tgz
```

记录 Git commit、包名和 SHA-256，通过公司批准的文件流转渠道将同一个包送到蓝、黄服务器。黄区禁止为下载软件包临时开放互联网访问。

服务器收到后验证：

```bash
sha256sum /tmp/openresty-waf-release.tgz
```

输出必须与发布记录一致。

## 10. 全新部署

只有 `/opt/openresty-waf` 不存在时使用本节。

### 10.1 解压

```bash
sudo mkdir -p /opt
sudo tar -xzf /tmp/openresty-waf-release.tgz -C /opt
cd /opt/openresty-waf
```

根据第 7、8 节生成本节点配置和正式规则。

### 10.2 节点准备

黄端：

```bash
cd /opt/openresty-waf
sudo NODE_ROLE=yellow bash scripts/server-setup.sh
```

蓝端：

```bash
cd /opt/openresty-waf
sudo NODE_ROLE=blue bash scripts/server-setup.sh
```

脚本会创建或修正：

```text
/data/openresty-waf/audit/access.log
/data/openresty-waf/audit/rejected.log
/data/openresty-waf/log/error.log
```

并检查规则、占位符和 OpenResty 配置。

### 10.3 安装 systemd 单元

```bash
sudo install -o root -g root -m 0644 \
  /opt/openresty-waf/deploy/openresty-waf@.service \
  /etc/systemd/system/openresty-waf@.service
sudo systemctl daemon-reload
```

### 10.4 SELinux

先检查：

```bash
getenforce
```

仅输出 `Enforcing` 时，由现场管理员按安全基线配置：

```bash
sudo semanage fcontext -a -t httpd_sys_content_t '/opt/openresty-waf(/.*)?'
sudo semanage fcontext -a -t httpd_log_t '/data/openresty-waf(/.*)?'
sudo restorecon -Rv /opt/openresty-waf /data/openresty-waf
sudo setsebool -P httpd_can_network_connect 1
```

已有 fcontext 规则时将 `-a` 改为 `-m`。非标准监听端口是否需要登记为 `http_port_t` 由现场管理员确认。

### 10.5 启动顺序

先黄端：

```bash
/data/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx-yellow.conf -t
sudo systemctl enable --now openresty-waf@yellow.service
```

再蓝端：

```bash
/data/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx-blue.conf -t
sudo systemctl enable --now openresty-waf@blue.service
```

启动前必须完成四层来源、目标、方向和端口验收。

## 11. 已运行旧版本的升级

### 11.1 升级性质

以下变化使本次升级不能只替换单个文件：

- 规则由 `method + path` 改为 `host + method + path`；
- 顶层增加 `max_response_body_bytes`；
- 每条规则必须增加 `host` 和 `responses`；
- Nginx 增加 internal 响应捕获 location；
- 黄 WAF 由单后端模板改为双固定目标；
- Lua、审计变量和日志格式同步变化。

新代码加载旧规则会失败，新旧蓝黄配置在 Host 传递方式上也不兼容。因此单实例链路需要维护窗口。若要求零停机，必须另建并行蓝/黄链路并通过批准的 DNS 或负载均衡方案切换。

### 11.2 旧服务运行期间预装

蓝、黄服务器分别执行，发布编号由运维填写：

```bash
WAF_RELEASE_ID='填写发布编号'
WAF_RELEASE_DIR="/opt/openresty-waf-${WAF_RELEASE_ID}"
WAF_PACKAGE='/tmp/openresty-waf-release.tgz'

test ! -e "$WAF_RELEASE_DIR"
sudo install -d -o root -g nobody -m 0750 "$WAF_RELEASE_DIR"
sudo tar -xzf "$WAF_PACKAGE" --strip-components=1 -C "$WAF_RELEASE_DIR"
```

`test` 必须成功；如果目录已经存在，应停止操作并核对，不能覆盖或混用上一次预装目录。

黄端生成配置：

```bash
sudo cp \
  "$WAF_RELEASE_DIR/conf/nginx-yellow.conf.template" \
  "$WAF_RELEASE_DIR/conf/nginx-yellow.conf"
sudo vi "$WAF_RELEASE_DIR/conf/nginx-yellow.conf"
sudo vi "$WAF_RELEASE_DIR/conf/waf_rules.lua"
```

蓝端生成配置：

```bash
sudo cp \
  "$WAF_RELEASE_DIR/conf/nginx-blue.conf.template" \
  "$WAF_RELEASE_DIR/conf/nginx-blue.conf"
sudo vi "$WAF_RELEASE_DIR/conf/nginx-blue.conf"
sudo vi "$WAF_RELEASE_DIR/conf/waf_rules.lua"
```

不要将旧 Nginx 文件整体复制到新目录。蓝、黄两端的正式 `waf_rules.lua` 应由同一批准版本生成。

黄端预检：

```bash
sudo PREFIX="$WAF_RELEASE_DIR" NODE_ROLE=yellow \
  bash "$WAF_RELEASE_DIR/scripts/server-setup.sh"
```

蓝端预检：

```bash
sudo PREFIX="$WAF_RELEASE_DIR" NODE_ROLE=blue \
  bash "$WAF_RELEASE_DIR/scripts/server-setup.sh"
```

预检必须显示正式 ALLOW 规则，不能是空白名单。两端规则 SHA-256 必须一致。

### 11.3 切换前备份

两台服务器分别执行，节点角色填写 `blue` 或 `yellow`：

```bash
WAF_RELEASE_ID='填写发布编号'
WAF_NODE_ROLE='填写节点角色'

sudo tar -C /opt -czf \
  "/root/openresty-waf-before-${WAF_RELEASE_ID}-${WAF_NODE_ROLE}.tgz" \
  openresty-waf
```

确认备份文件存在，并记录旧目录、安装包、规则和节点配置的 SHA-256。

### 11.4 维护窗口切换顺序

1. 先停止或从流量入口摘除蓝 WAF，阻止新请求进入；
2. 停止黄 WAF，切换黄端完整目录；
3. 启动并验证黄 WAF；
4. 切换蓝端完整目录；
5. 启动蓝 WAF；
6. 完成全链路验收后恢复业务流量。

先在蓝服务器停止入口：

```bash
sudo systemctl stop openresty-waf@blue
sudo systemctl is-active openresty-waf@blue
```

预期为 `inactive`。

黄服务器切换：

```bash
WAF_RELEASE_ID='填写发布编号'
WAF_RELEASE_DIR="/opt/openresty-waf-${WAF_RELEASE_ID}"
WAF_PREVIOUS_DIR="/opt/openresty-waf-prev-${WAF_RELEASE_ID}"

test ! -e "$WAF_PREVIOUS_DIR"
sudo systemctl stop openresty-waf@yellow
sudo mv /opt/openresty-waf "$WAF_PREVIOUS_DIR"
sudo mv "$WAF_RELEASE_DIR" /opt/openresty-waf
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
  sudo restorecon -Rv /opt/openresty-waf
fi
sudo install -o root -g root -m 0644 \
  /opt/openresty-waf/deploy/openresty-waf@.service \
  /etc/systemd/system/openresty-waf@.service
sudo systemctl daemon-reload
sudo systemctl start openresty-waf@yellow
sudo systemctl status openresty-waf@yellow --no-pager
```

黄端验证通过后，在蓝服务器切换：

```bash
WAF_RELEASE_ID='填写发布编号'
WAF_RELEASE_DIR="/opt/openresty-waf-${WAF_RELEASE_ID}"
WAF_PREVIOUS_DIR="/opt/openresty-waf-prev-${WAF_RELEASE_ID}"

test ! -e "$WAF_PREVIOUS_DIR"
sudo mv /opt/openresty-waf "$WAF_PREVIOUS_DIR"
sudo mv "$WAF_RELEASE_DIR" /opt/openresty-waf
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
  sudo restorecon -Rv /opt/openresty-waf
fi
sudo install -o root -g root -m 0644 \
  /opt/openresty-waf/deploy/openresty-waf@.service \
  /etc/systemd/system/openresty-waf@.service
sudo systemctl daemon-reload
sudo systemctl start openresty-waf@blue
sudo systemctl status openresty-waf@blue --no-pager
```

SELinux Enforcing 环境中 `restorecon` 失败必须停止切换并处理，不能忽略。

### 11.5 升级回滚

新旧版本必须两端整体回滚：

1. 停止或摘除蓝端入口；
2. 停止蓝、黄 WAF；
3. 黄端将新目录改名保留，把对应 `WAF_PREVIOUS_DIR` 恢复为 `/opt/openresty-waf`；
4. 恢复黄端 systemd 单元、SELinux 上下文并启动黄端；
5. 蓝端执行相同恢复并启动；
6. 验证原业务恢复；
7. 最后按审批方案回滚新增 DNS 和四层 ACL。

先停止蓝端入口，然后在黄服务器执行：

```bash
WAF_RELEASE_ID='填写发布编号'
WAF_PREVIOUS_DIR="/opt/openresty-waf-prev-${WAF_RELEASE_ID}"
WAF_FAILED_DIR="/opt/openresty-waf-failed-${WAF_RELEASE_ID}"

test ! -e "$WAF_FAILED_DIR"
sudo systemctl stop openresty-waf@yellow
sudo mv /opt/openresty-waf "$WAF_FAILED_DIR"
sudo mv "$WAF_PREVIOUS_DIR" /opt/openresty-waf
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
  sudo restorecon -Rv /opt/openresty-waf
fi
sudo install -o root -g root -m 0644 \
  /opt/openresty-waf/deploy/openresty-waf@.service \
  /etc/systemd/system/openresty-waf@.service
sudo systemctl daemon-reload
sudo systemctl start openresty-waf@yellow
sudo systemctl status openresty-waf@yellow --no-pager
```

黄端恢复并验证后，在蓝服务器执行相同步骤，将服务名改为 `openresty-waf@blue`，最后启动蓝端并进行原业务验收。

不要删除失败版本目录，先保留现场证据。不得通过开放直连、允许未知字段或关闭响应校验完成故障绕行。

## 12. 配置检查与服务操作

黄端：

```bash
/data/openresty/bin/openresty \
  -p /opt/openresty-waf/ \
  -c conf/nginx-yellow.conf \
  -t
sudo systemctl status openresty-waf@yellow --no-pager
```

蓝端：

```bash
/data/openresty/bin/openresty \
  -p /opt/openresty-waf/ \
  -c conf/nginx-blue.conf \
  -t
sudo systemctl status openresty-waf@blue --no-pager
```

只有规则和配置检查全部成功后才能 start 或 reload。

## 13. 验收

### 13.1 WAF 基础生效验证

使用已登记业务 Host 请求一个未登记路径：

```bash
WAF_TEST_IP='填写WAF监听IP'
WAF_TEST_PORT='填写WAF监听端口'
WAF_TEST_HOST='填写业务Host'
WAF_TEST_PATH='/__waf_check__/probe'

curl --connect-timeout 3 --max-time 10 -sS -i \
  -H "Host: ${WAF_TEST_HOST}" \
  "http://${WAF_TEST_IP}:${WAF_TEST_PORT}${WAF_TEST_PATH}"
```

预期：

- HTTP `403`；
- 响应包含 `not_in_whitelist`；
- 对应节点审计日志包含 `deny_request`。

黄 WAF 的基础验证应从蓝 WAF 服务器发起，只用于运维验收，不得固化为业务直连方式。

### 13.2 双 Host 和响应验收

| 用例 | 预期 |
|---|---|
| Host A + A 请求 + A 响应 | 放行，只到达目标 A |
| Host B + B 请求 + B 响应 | 放行，只到达目标 B |
| A 请求体发送到 Host B | `400/422 request_body` |
| B 请求体发送到 Host A | `400/422 request_body` |
| 未登记 Host | `444` 或 `403` |
| 未登记 method/path | `403 not_in_whitelist` |
| 任意 query string | `403 query_not_allowed` |
| 非 JSON 请求 | `415 unsupported_media_type` |
| 非法 JSON | `400 invalid_json` |
| 请求未知字段或错误类型 | `400/422 request_body` |
| 请求超过 16 KiB | `413 request_body_too_large` |
| 未登记响应状态码 | `502 response_status_not_allowed` |
| 非 JSON 响应 | `502 response_unsupported_media_type` |
| 压缩响应 | `502 response_content_encoding_not_allowed` |
| 非法响应 JSON | `502 invalid_upstream_json` |
| 响应不符合当前 Host schema | `502 response_body` |
| 响应超过规则或 1 MiB | `502 response_body_too_large` |
| 绕过任一 WAF 直连目标 | 四层拒绝 |

异常响应测试必须使用测试桩或业务测试环境，不得在生产服务临时注入错误响应。响应拒绝时不得向调用方回显原始上游正文。

### 13.3 验收记录

| 节点/链路 | 时间 | 用例 | HTTP 结果 | 审计记录 | 结论 | 执行人 |
|---|---|---|---|---|---|---|
| 蓝 WAF |  | 基础拒绝 |  |  |  |  |
| 黄 WAF |  | 基础拒绝 |  |  |  |  |
| Host A |  | 正向及响应 |  |  |  |  |
| Host B |  | 正向及响应 |  |  |  |  |
| 交叉契约 |  | 拒绝 |  |  |  |  |
| 四层旁路 |  | 拒绝 |  |  |  |  |

## 14. 审计

日志位置：

```text
/data/openresty-waf/audit/access.log
/data/openresty-waf/audit/rejected.log
/data/openresty-waf/log/error.log
```

业务审计至少包含：

```text
node_role
trace_id
remote_addr
request_host
method
path
rule_id
action
reason
request_body_bytes
request_body_sha256
upstream_addr
upstream_status
response_schema
response_body_bytes
response_body_sha256
forward_response_bytes
forward_response_sha256
```

不得记录 query、请求正文或响应正文原文。蓝、黄日志应能通过 `trace_id` 关联，并按公司要求配置轮转、留存、转储和防篡改。

## 15. 日常变更

### 15.1 只新增规则

保留已有规则的前提下新增 Host 或接口时：

1. 完成审批和规则检查；
2. 将相同规则文件先同步黄端并 reload；
3. 验证黄端后同步蓝端并 reload；
4. 执行正向、拒绝、响应和旁路验收。

黄端先具备规则后，蓝端才可以开始转发新接口。

### 15.2 删除或收紧规则

删除接口或先停止蓝端转发的收紧操作：

1. 先更新蓝端，使入口停止接收该流量；
2. 验证蓝端拒绝；
3. 再更新黄端；
4. 确认目标服务和四层 ACL 按计划收回。

### 15.3 不兼容契约或运行代码升级

请求/响应契约不能兼容新旧流量，或修改 Lua、Nginx、审计配置时，应按第 11 节维护窗口整体升级，不得让蓝、黄节点长时间运行不同版本。

## 16. 常见故障

| 现象 | 检查项 |
|---|---|
| 服务启动失败 | `journalctl`、OpenResty `-t`、文件权限和 SELinux |
| 规则检查失败 | Host、重复路由、schema 引用、responses 和大小限制 |
| 所有请求 403 | 是否误用包内空白名单，Host/method/path 是否一致 |
| 空响应或 444 | 请求 Host 是否匹配模板 `server_name` |
| 请求 400/422 | Content-Type、JSON、必填字段、类型、未知字段和范围 |
| `response_status_not_allowed` | 实际状态码是否逐条登记 |
| `response_body` | 当前 Host/状态码绑定的响应 schema 是否完整准确 |
| `response_body_too_large` | 状态码上限、全局 1 MiB 上限及异常上游输出 |
| `upstream_capture_failed` | internal location、四层可达性、目标服务和超时 |
| 蓝端 502 | 蓝到黄四层策略、黄端 Host、黄端校验和服务状态 |
| 黄端 502 | 黄端到固定目标的地址、端口、响应类型和契约 |
| 审计无记录 | access_log、目录权限、systemd 沙箱和日志转储 |

## 17. 最终上线检查表

- [ ] 已对照安全架构图和白名单台账；
- [ ] 两个业务 Host、目标地址、端口和后端 Host 已确认；
- [ ] 两套请求 schema 和逐状态码响应 schema 已审批；
- [ ] 四层来源、目标、方向和端口已验收；
- [ ] 未登记来源和绕过路径实测失败；
- [ ] 蓝、黄使用同一安装包、Lua 版本和规则文件；
- [ ] 活动白名单不是仓库默认空配置；
- [ ] 规则检查为 `0 error`；
- [ ] 两端 OpenResty `-t` 成功；
- [ ] 正向、交叉、异常响应、超限和旁路用例通过；
- [ ] 日志可查询、可关联且不含正文；
- [ ] 容量、日志轮转和集中转储已确认；
- [ ] 旧版本目录和安装包可完整回滚；
- [ ] 变更窗口、负责人和回滚触发条件已记录。
