# 双 WAF 部署、升级与运维交接手册

本文是蓝区、黄区双 WAF 的唯一部署与运维交接文档，供运维、安全和业务负责人共同使用。内容覆盖首次部署、旧版本直接覆盖升级、mTLS 证书、活动规则、启动验收、日常变更、日志治理、故障处理和回滚。

## 1. 部署目标与边界

生产流量路径固定为：

```text
蓝区调用方
  → 蓝区 WAF
  → mTLS WAF-to-WAF
  → 黄区 WAF
  → 黄区已审批目标服务
```

基本原则：

1. WAF 核心不内置业务 URL；Host、method、path、请求 schema、响应状态和响应 schema 全部由运维活动规则决定。
2. 蓝、黄两侧加载同一份 `conf/waf_rules.lua`，版本和 SHA-256 必须一致。
3. 未登记 URL、字段、状态码或身份默认拒绝。
4. 蓝 WAF 只能访问黄 WAF，不能绕过黄 WAF 直连目标服务。
5. 黄 WAF 只接受已登记的蓝 WAF 客户端证书身份。
6. 两区位于不同服务器，均使用本机 `/data/openresty-waf/` 持久化日志；节点来源由日志中的角色字段和主机元数据区分。
7. 本项目只实现七层 WAF，不替代防火墙、DLP、Jumpserver、AD、EDR、日志平台或文件外发审批。

仓库和安装包自带的活动规则是安全占位配置：

```text
version   = UNCONFIGURED-DENY-ALL
direction = not_configured
whitelist = {}
```

该配置不会放行任何业务 URL，并且不能通过生产启动检查。运维必须先安装审批后的正式活动规则。

## 2. 交付文件

安装包不包含 OpenResty 程序，直接使用两台服务器已有的 `/data/openresty/`。本项目文件安装到 `/opt/openresty-waf/`，审计日志写入 `/data/openresty-waf/`；三个目录用途不同，不存在目录覆盖冲突。

| 文件 | 用途 |
|---|---|
| `conf/nginx-blue.conf.template` | 蓝区 WAF 生产模板 |
| `conf/nginx-yellow.conf.template` | 黄区 WAF 生产模板 |
| `conf/waf_rules.lua` | 运维活动规则；安装包内默认全部拒绝 |
| `conf/waf_rules_knowledge_example.lua` | 知识库接口规则示例；生产不会自动加载 |
| `scripts/check_rules.lua` | 活动规则静态检查 |
| `scripts/server-setup.sh` | 目录、权限、规则和 OpenResty 配置检查 |
| `scripts/package.sh` | 离线安装包生成脚本 |
| `deploy/openresty-waf@.service` | 蓝、黄实例共用的 systemd 模板 |
| `docs/WAF规则配置指南.md` | 活动规则字段说明 |
| `docs/绿蓝黄数据链路白名单台账.md` | 跨区链路和审批门禁 |

生产运行配置分别是：

```text
蓝区：/opt/openresty-waf/conf/nginx-blue.conf
黄区：/opt/openresty-waf/conf/nginx-yellow.conf
```

`conf/nginx.conf` 仅用于本地演示，不是生产配置。

## 3. 上线前材料清单

材料未收齐时不得通过放宽规则、关闭证书校验或绕过 WAF 临时上线。

### 3.1 公共材料

- 变更单或审批编号。
- 本次规则的正式 `version` 和 `direction`。
- 审批后的 `conf/waf_rules.lua`。
- 蓝、黄两侧一致的规则 SHA-256。
- 上线窗口、业务负责人、运维负责人、安全审批人。
- 正向、反向验收用例和回滚条件。
- 日志留存期、磁盘告警阈值和防篡改转储方案。

### 3.2 蓝区材料

- 蓝 WAF 监听 IP、端口和 Host。
- 黄 WAF IP、端口、Host 和服务端证书名称。
- 蓝 WAF 客户端证书和私钥。
- 用于验证黄 WAF 的 CA 证书。
- 允许访问蓝 WAF 的来源范围。

### 3.3 黄区材料

- 黄 WAF 监听 IP、端口和 Host。
- 蓝 WAF 客户端证书 Subject DN。
- 黄 WAF 服务端证书和私钥。
- 用于验证蓝 WAF 客户端证书的 CA 证书。
- 黄区目标服务 IP、端口、协议和 Host。
- 黄 WAF 到目标服务的最小网络权限。

若黄 WAF 到目标服务使用 HTTPS，还必须配置目标服务 CA、证书名称和 `proxy_ssl_verify on`；不得使用 `proxy_ssl_verify off`。

## 4. mTLS 证书

### 4.1 证书作用

蓝 WAF 与黄 WAF 之间使用双向 TLS：

- 黄 WAF 服务端证书证明黄 WAF 身份，并加密传输。
- 蓝 WAF 客户端证书证明蓝 WAF 身份。
- 蓝 WAF 使用黄区 CA 验证黄 WAF。
- 黄 WAF 使用蓝区客户端 CA 验证蓝 WAF，并额外精确匹配客户端 Subject DN。

证书文件不需要导入操作系统证书库。OpenResty 直接读取配置中指定的证书文件，但证书、路径、权限、名称和 Subject 必须正确。

### 4.2 文件位置

蓝区服务器：

```text
/opt/openresty-waf/certs/blue-waf-client.crt
/opt/openresty-waf/certs/blue-waf-client.key
/opt/openresty-waf/certs/yellow-waf-ca.crt
```

黄区服务器：

```text
/opt/openresty-waf/certs/yellow-waf-server.crt
/opt/openresty-waf/certs/yellow-waf-server.key
/opt/openresty-waf/certs/blue-waf-client-ca.crt
```

私钥不得跨服务器复制：

- `blue-waf-client.key` 只保存在蓝区 WAF。
- `yellow-waf-server.key` 只保存在黄区 WAF。
- 私钥不得提交到 Git、安装包或运维文档。

### 4.3 证书要求

- 黄 WAF 服务端证书的 SAN 必须包含 `__YELLOW_WAF_TLS_NAME__` 配置值。
- 黄 WAF 服务端证书应具备 `serverAuth` 用途。
- 蓝 WAF 客户端证书应具备 `clientAuth` 用途。
- 证书必须在有效期内，服务器时间必须正确。
- 证书链必须能被对应 CA 文件验证。
- 证书和私钥必须匹配。
- 当前模板按非交互方式启动；加密私钥需要另行配置安全的密码加载机制，不能依赖人工输入密码。

### 4.4 安装证书

蓝区服务器：

```bash
sudo install -d -o root -g nobody -m 0750 /opt/openresty-waf/certs
sudo install -o root -g nobody -m 0640 blue-waf-client.crt /opt/openresty-waf/certs/blue-waf-client.crt
sudo install -o root -g nobody -m 0640 blue-waf-client.key /opt/openresty-waf/certs/blue-waf-client.key
sudo install -o root -g nobody -m 0640 yellow-waf-ca.crt /opt/openresty-waf/certs/yellow-waf-ca.crt
```

黄区服务器：

```bash
sudo install -d -o root -g nobody -m 0750 /opt/openresty-waf/certs
sudo install -o root -g nobody -m 0640 yellow-waf-server.crt /opt/openresty-waf/certs/yellow-waf-server.crt
sudo install -o root -g nobody -m 0640 yellow-waf-server.key /opt/openresty-waf/certs/yellow-waf-server.key
sudo install -o root -g nobody -m 0640 blue-waf-client-ca.crt /opt/openresty-waf/certs/blue-waf-client-ca.crt
```

### 4.5 检查证书

查看证书身份、签发方和有效期：

```bash
openssl x509 -in yellow-waf-server.crt -noout -subject -issuer -dates -ext subjectAltName -ext extendedKeyUsage
openssl x509 -in blue-waf-client.crt -noout -subject -issuer -dates -ext extendedKeyUsage
```

检查证书链：

```bash
openssl verify -CAfile yellow-waf-ca.crt yellow-waf-server.crt
openssl verify -CAfile blue-waf-client-ca.crt blue-waf-client.crt
```

检查证书和私钥是否匹配；同一组的两条摘要必须一致：

```bash
openssl x509 -in yellow-waf-server.crt -pubkey -noout | openssl sha256
openssl pkey -in yellow-waf-server.key -pubout | openssl sha256

openssl x509 -in blue-waf-client.crt -pubkey -noout | openssl sha256
openssl pkey -in blue-waf-client.key -pubout | openssl sha256
```

获取蓝 WAF 客户端证书 Subject：

```bash
openssl x509 -in blue-waf-client.crt -noout -subject -nameopt RFC2253
```

将输出中 `subject=` 后面的完整值填入黄区模板的 `__BLUE_WAF_CLIENT_SUBJECT_DN__`。不得凭证书文件名猜测 Subject。

## 5. 活动规则配置

正式活动规则只由运维维护的 `conf/waf_rules.lua` 决定。每条 URL 至少包含：

```lua
{
  id = "审批台账中的稳定规则 ID",
  methods = { "POST" },
  path = "/approved/path",
  request_schema = "approved_request",
  response_schemas = {
    ["200"] = "approved_response",
    ["422"] = "approved_error",
  },
}
```

正式文件必须满足：

```lua
version = "审批后的唯一版本"
direction = "blue_to_yellow"
example = false
```

规则要求：

1. method 和 path 必须精确登记，不允许生产白名单使用正则 path。
2. 当前版本禁止所有 query string。
3. 配置 `request_schema` 表示必须有合法 JSON 请求体；不配置则禁止请求体。
4. 每个允许的响应状态码必须绑定响应 schema。
5. object 必须设置 `additional_properties=false`。
6. 未登记响应状态、非 JSON 响应、超限响应或 schema 不匹配响应统一替换为通用 `502`。
7. 规则版本必须关联审批记录，不能使用 `EXAMPLE` 或 `UNCONFIGURED` 版本。

知识库示例不会被生产模板自动加载。需要使用时，必须按审批结果生成正式活动规则，而不是直接把示例当成生产授权。

在蓝、黄两侧分别执行：

```bash
cd /opt/openresty-waf
/data/openresty/luajit/bin/luajit scripts/check_rules.lua --production conf/waf_rules.lua
sha256sum conf/waf_rules.lua
```

两侧输出必须满足：

- 规则检查为 `0 error`。
- `version`、`direction` 和规则条目一致。
- SHA-256 完全相同。

完整字段说明见 `docs/WAF规则配置指南.md`。

## 6. 首次部署

通过堡垒机文件传输、受控 SFTP 或公司批准的介质/导入流程，将交付的安装包传入对应分区。不得建立绕过公司审批、DLP 或审计的临时传输通道。

### 6.1 解压

仅在首次部署、`/opt/openresty-waf` 不存在时执行：

```bash
sudo mkdir -p /opt
sudo tar -xzf /tmp/openresty-waf.tgz -C /opt
```

如果目录已经存在，使用第 7 节的直接覆盖升级步骤。

### 6.2 配置黄区节点

```bash
cd /opt/openresty-waf
sudo cp conf/nginx-yellow.conf.template conf/nginx-yellow.conf
sudo vi conf/nginx-yellow.conf
```

必须替换：

- `__YELLOW_WAF_LISTEN_IP__`
- `__YELLOW_WAF_PORT__`
- `__YELLOW_WAF_HOST__`
- `__BLUE_WAF_CLIENT_SUBJECT_DN__`
- `__PROTECTED_SERVICE_IP__`
- `__PROTECTED_SERVICE_PORT__`
- `__PROTECTED_SERVICE_SCHEME__`
- `__PROTECTED_SERVICE_HOST__`
- `__WAF_RULE_APPROVAL_ID__`

然后安装正式 `conf/waf_rules.lua` 和黄区证书，检查残留占位符：

```bash
grep -En '__[A-Z0-9_]+__' conf/nginx-yellow.conf
```

正常情况下无输出。

运行准备脚本：

```bash
sudo NODE_ROLE=yellow bash /opt/openresty-waf/scripts/server-setup.sh
```

### 6.3 配置蓝区节点

```bash
cd /opt/openresty-waf
sudo cp conf/nginx-blue.conf.template conf/nginx-blue.conf
sudo vi conf/nginx-blue.conf
```

必须替换：

- `__BLUE_WAF_LISTEN_IP__`
- `__BLUE_WAF_LISTEN_PORT__`
- `__BLUE_WAF_HOST__`
- `__YELLOW_WAF_IP__`
- `__YELLOW_WAF_PORT__`
- `__YELLOW_WAF_HOST__`
- `__YELLOW_WAF_TLS_NAME__`
- `__WAF_RULE_APPROVAL_ID__`

然后安装与黄区完全一致的 `conf/waf_rules.lua` 和蓝区证书，检查残留占位符：

```bash
grep -En '__[A-Z0-9_]+__' conf/nginx-blue.conf
```

运行准备脚本：

```bash
sudo NODE_ROLE=blue bash /opt/openresty-waf/scripts/server-setup.sh
```

### 6.4 SELinux 与目录权限

`server-setup.sh` 会创建：

```text
/data/openresty-waf/audit/access.log
/data/openresty-waf/audit/rejected.log
/data/openresty-waf/log/error.log
```

在 SELinux Enforcing 环境中，根据现有策略使用 `semanage fcontext -a` 或 `-m` 配置：

```bash
sudo semanage fcontext -a -t httpd_sys_content_t '/opt/openresty-waf(/.*)?'
sudo semanage fcontext -a -t httpd_log_t '/data/openresty-waf(/.*)?'
sudo restorecon -Rv /opt/openresty-waf /data/openresty-waf
sudo setsebool -P httpd_can_network_connect 1
```

非标准监听端口还需按现场端口配置 `http_port_t`。不得为方便排障关闭 SELinux。

### 6.5 安装和启动 systemd 服务

蓝、黄两台服务器都执行：

```bash
sudo cp /opt/openresty-waf/deploy/openresty-waf@.service /etc/systemd/system/
sudo systemctl daemon-reload
```

先启动黄区：

```bash
sudo systemctl enable --now openresty-waf@yellow
sudo systemctl status openresty-waf@yellow --no-pager
```

再启动蓝区：

```bash
sudo systemctl enable --now openresty-waf@blue
sudo systemctl status openresty-waf@blue --no-pager
```

### 6.6 网络最小放行

| 方向 | 允许目标 | 限制 |
|---|---|---|
| 蓝区调用方 → 蓝 WAF | 蓝 WAF 已审批监听 IP/端口 | 只允许登记来源 |
| 蓝 WAF → 黄 WAF | 黄 WAF mTLS IP/端口 | 只允许蓝 WAF 来源 |
| 黄 WAF → 黄区目标服务 | 已审批服务 IP/端口 | 只允许黄 WAF 来源 |

必须禁止蓝区服务器直连黄区目标服务、非蓝 WAF 身份访问黄 WAF、黄区主动出网及任何绕过两侧 WAF 的旁路。

## 7. 旧版本直接覆盖升级

本节适用于已在 `/opt/openresty-waf` 部署过旧版本，并希望直接覆盖更新的场景。升级顺序为：黄区服务器先更新并启动，蓝区服务器随后更新并启动。

### 7.1 升级前准备

升级前必须准备好：

- 新安装包 `/tmp/openresty-waf.tgz`。
- 新格式且已审批的 `waf_rules.lua`；旧版规则格式不能直接沿用。
- 当前节点已经渲染完成的 `nginx-yellow.conf` 或 `nginx-blue.conf`。
- 本节点所需的证书文件。
- 维护窗口和回滚负责人。

安装包中的 `conf/waf_rules.lua` 是默认全部拒绝配置。直接覆盖后必须立即安装正式规则，否则生产检查会拒绝启动。

### 7.2 黄区服务器覆盖更新

```bash
ROLE=yellow
BACKUP_TAG="$(date +%Y%m%d%H%M%S)"
BACKUP_FILE="/root/openresty-waf-backup-${ROLE}-${BACKUP_TAG}.tgz"

sudo systemctl stop openresty-waf.service 2>/dev/null || true
sudo systemctl stop "openresty-waf@$ROLE.service" 2>/dev/null || true

sudo tar -C /opt -czf "$BACKUP_FILE" openresty-waf
echo "备份文件：$BACKUP_FILE"

sudo tar -xzf /tmp/openresty-waf.tgz -C /opt --overwrite
```

覆盖完成后：

1. 从新模板重新生成 `conf/nginx-yellow.conf` 并填写全部占位符。
2. 安装审批后的新格式 `conf/waf_rules.lua`。
3. 确认证书位于第 4 节规定路径。
4. 确认规则 SHA-256 与蓝区待发布文件一致。

执行：

```bash
sudo NODE_ROLE=yellow bash /opt/openresty-waf/scripts/server-setup.sh
sudo cp /opt/openresty-waf/deploy/openresty-waf@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now openresty-waf@yellow
sudo systemctl status openresty-waf@yellow --no-pager
```

### 7.3 蓝区服务器覆盖更新

```bash
ROLE=blue
BACKUP_TAG="$(date +%Y%m%d%H%M%S)"
BACKUP_FILE="/root/openresty-waf-backup-${ROLE}-${BACKUP_TAG}.tgz"

sudo systemctl stop openresty-waf.service 2>/dev/null || true
sudo systemctl stop "openresty-waf@$ROLE.service" 2>/dev/null || true

sudo tar -C /opt -czf "$BACKUP_FILE" openresty-waf
echo "备份文件：$BACKUP_FILE"

sudo tar -xzf /tmp/openresty-waf.tgz -C /opt --overwrite
```

覆盖完成后：

1. 从新模板重新生成 `conf/nginx-blue.conf` 并填写全部占位符。
2. 安装与黄区完全一致的 `conf/waf_rules.lua`。
3. 确认证书位于第 4 节规定路径。
4. 核对蓝、黄两侧规则 SHA-256。

执行：

```bash
sudo NODE_ROLE=blue bash /opt/openresty-waf/scripts/server-setup.sh
sudo cp /opt/openresty-waf/deploy/openresty-waf@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now openresty-waf@blue
sudo systemctl status openresty-waf@blue --no-pager
```

新链路验收通过后，禁用旧单实例服务，但暂时保留旧 service 文件和备份包：

```bash
sudo systemctl disable openresty-waf.service
```

### 7.4 后续双 WAF 版本覆盖升级

已经使用 `openresty-waf@blue`、`openresty-waf@yellow` 的环境再次升级时，同样先备份再覆盖。覆盖前单独备份以下现场文件：

```text
conf/waf_rules.lua
conf/nginx-blue.conf 或 conf/nginx-yellow.conf
certs/
```

若新模板发生变化，应以新模板重新渲染，不能无条件恢复旧 nginx 配置。规则发布仍按“黄端检查和 reload → 蓝端检查和 reload → 端到端验收”的顺序执行。

## 8. 上线验收

### 8.1 静态检查

两台服务器分别执行：

```bash
cd /opt/openresty-waf
/data/openresty/luajit/bin/luajit scripts/check_rules.lua --production conf/waf_rules.lua
sha256sum conf/waf_rules.lua
```

按节点执行 OpenResty 检查：

```bash
sudo /data/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx-yellow.conf -t
sudo /data/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx-blue.conf -t
```

### 8.2 正向用例

- 已登记 Host、method、path 和请求体能够经过蓝、黄两侧 WAF。
- 黄区目标服务返回的状态码和 JSON 正文符合响应 schema。
- 调用方收到 `X-Request-ID`。
- 蓝、黄日志中存在相同 `trace_id`。

示例命令中的 Host、地址、路径和请求文件必须替换为审批值：

```bash
BLUE_WAF_HOST='填写审批后的蓝WAF Host'
BLUE_WAF_IP='填写审批后的蓝WAF IP'
BLUE_WAF_PORT='填写审批后的蓝WAF端口'
APPROVED_PATH='/填写审批后的路径'

curl -i -H "Host: $BLUE_WAF_HOST" \
  "http://${BLUE_WAF_IP}:${BLUE_WAF_PORT}${APPROVED_PATH}"

curl -i \
  -H "Host: $BLUE_WAF_HOST" \
  -H 'Content-Type: application/json' \
  --data-binary @approved-request.json \
  "http://${BLUE_WAF_IP}:${BLUE_WAF_PORT}${APPROVED_PATH}"
```

### 8.3 拒绝用例

至少验证：

- 未登记 Host。
- 未登记 method 或 path。
- 带 query string 的请求。
- 无 schema 接口携带请求体。
- JSON 缺少必填字段、字段类型错误、未知字段或超限。
- 上游返回未登记状态码、非 JSON、未知字段或超限正文。
- 未携带蓝 WAF 客户端证书或使用错误证书访问黄 WAF。
- 停止任一 WAF 后不能旁路访问黄区目标服务。

### 8.4 日志检查

蓝、黄服务器使用相同的本机路径：

```bash
sudo tail -n 50 /data/openresty-waf/audit/access.log
sudo tail -n 50 /data/openresty-waf/audit/rejected.log
sudo tail -n 50 /data/openresty-waf/log/error.log
```

验收标准：

- 接受和拒绝请求均有记录。
- 同一请求可通过 `trace_id` 在两侧关联。
- 日志包含节点角色、证书身份、rule ID、规则版本、动作和原因。
- 日志不包含 query string、请求正文、响应正文、私钥或凭证。

## 9. 日常运维

### 9.1 服务命令

蓝区：

```bash
sudo systemctl status openresty-waf@blue --no-pager
sudo systemctl reload openresty-waf@blue
sudo journalctl -u openresty-waf@blue -n 100 --no-pager
```

黄区：

```bash
sudo systemctl status openresty-waf@yellow --no-pager
sudo systemctl reload openresty-waf@yellow
sudo journalctl -u openresty-waf@yellow -n 100 --no-pager
```

每次 reload 前必须先运行对应的 `openresty -t`。

### 9.2 规则变更

1. 业务和安全完成白名单审批。
2. 修改正式 `conf/waf_rules.lua`，更新唯一 `version`。
3. 在开发或验证环境执行规则检查和测试。
4. 将完全相同的文件传到黄、蓝两侧。
5. 两侧分别执行生产规则检查并核对 SHA-256。
6. 先 reload 黄区，再 reload 蓝区。
7. 执行本次规则对应的放行和拒绝用例。
8. 保存变更单、规则哈希和验收记录。

不得只修改一侧规则，不得在故障期间临时扩大白名单。

### 9.3 证书续期

定期检查：

```bash
openssl x509 -in /opt/openresty-waf/certs/yellow-waf-server.crt -noout -dates
openssl x509 -in /opt/openresty-waf/certs/blue-waf-client.crt -noout -dates
```

续期要求：

- 新证书的用途、SAN、Subject 和信任链必须符合第 4 节。
- CA 变更时必须协调两侧信任文件，不能单边替换。
- 替换文件后先执行 `openresty -t`，再 reload 对应实例。
- 续期后重新验证 mTLS 拒绝用例。

### 9.4 日志与告警

必须配置：

- `/data/openresty-waf/audit/*.log` 和 `/data/openresty-waf/log/error.log` 的轮转与留存。
- `/data` 使用率和 inode 告警。
- 审计日志停止增长告警。
- `deny_request`、`deny_response`、`misconfigured` 和 `upstream_unavailable` 突增告警。
- 证书临近过期告警。
- 非蓝 WAF 身份访问黄 WAF 告警。
- 向日志转储平台的防篡改转储。

## 10. 常见故障

| 现象 | 常见原因 | 处理 |
|---|---|---|
| 生产规则检查失败 | 仍是 `UNCONFIGURED`、`EXAMPLE` 或 `example=true` | 安装审批后的正式规则 |
| 提示残留占位符 | nginx 配置未渲染完整 | 填写所有 `__PLACEHOLDER__` |
| `certificate verify failed` | CA、有效期、SAN、时间或证书链错误 | 按第 4 节逐项检查 |
| 黄 WAF 返回证书身份拒绝 | `__BLUE_WAF_CLIENT_SUBJECT_DN__` 与实际 Subject 不一致 | 使用 OpenSSL 输出的完整 RFC2253 Subject |
| 蓝 WAF 返回通用 `502` | 黄端或目标服务状态、Content-Type、JSON 或 schema 不合规 | 用两侧相同 `trace_id` 查询审计原因 |
| `upstream_unavailable` | 网络、监听端口、服务状态或防火墙错误 | 检查最小放行链路和目标监听 |
| 日志不能写入 | 目录权限、SELinux 或 systemd `ReadWritePaths` 不正确 | 重新运行准备脚本并核对上下文 |
| 规则在一侧生效、另一侧未生效 | 文件或 reload 顺序不一致 | 核对版本、SHA-256 和两个实例状态 |

排障不得采用以下方式：

- 关闭 `proxy_ssl_verify` 或客户端证书验证。
- 临时允许任意 URL、任意 query 或任意字段。
- 让蓝区服务器绕过黄 WAF 直连目标服务。
- 在日志中记录请求或响应正文。
- 为方便测试开放黄区外网。

## 11. 回滚

### 11.1 直接覆盖升级回滚

如果新版本启动或验收失败，先停止新实例：

```bash
sudo systemctl disable --now openresty-waf@blue
# 黄区服务器将 blue 换成 yellow
```

使用升级前备份包覆盖恢复：

将 `BACKUP_FILE` 设置为升级时输出并记录的实际备份路径，例如：

```bash
BACKUP_FILE=/root/openresty-waf-backup-blue-20260728103000.tgz
sudo test -f "$BACKUP_FILE"
sudo tar -xzf "$BACKUP_FILE" -C /opt --overwrite
```

如果回滚到旧单实例版本：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now openresty-waf.service
```

如果回滚到上一版双 WAF，则恢复上一版活动规则、节点配置和证书后，按“黄端 → 蓝端”顺序启动或 reload。

### 11.2 回滚要求

- 不删除 `/data/openresty-waf`，保留升级和失败期间的审计证据。
- 回滚前确认旧白名单仍在有效审批期内，不能恢复已撤销或过期授权。
- 回滚后重新验证合法请求、拒绝请求和两端日志关联。
- 记录回滚原因、执行人、时间、规则版本和恢复结果。

## 12. 运维交接清单

交接完成前逐项确认：

- [ ] 蓝、黄服务器地址、角色和负责人已登记。
- [ ] 安装包版本已记录。
- [ ] 活动规则版本、审批编号和 SHA-256 已记录。
- [ ] 蓝、黄规则文件完全一致。
- [ ] 所有 nginx 占位符均已替换。
- [ ] 蓝、黄证书链、Subject、SAN、用途和有效期已确认。
- [ ] 私钥只保存在对应 WAF 服务器且权限正确。
- [ ] systemd 实例已启用，配置检查通过。
- [ ] 三段最小网络访问关系已实施，旁路已关闭。
- [ ] 正向、拒绝、mTLS 和旁路用例已验收。
- [ ] 两侧相同 `trace_id` 可以关联。
- [ ] 日志轮转、留存、磁盘告警和转储已配置。
- [ ] 证书过期监控已配置。
- [ ] 备份位置、回滚步骤和回滚负责人已登记。
- [ ] 业务、运维和安全负责人已签字或在变更单中确认。

以下信息不得从示例或架构图推断，必须由现场负责人填写：

| 待确认项 | 现场值/记录位置 |
|---|---|
| 蓝 WAF IP、端口、Host |  |
| 黄 WAF IP、端口、Host |  |
| 黄 WAF TLS 名称 |  |
| 蓝 WAF 客户端 Subject DN |  |
| 黄区目标服务地址、协议和 Host |  |
| 规则审批编号和有效期 |  |
| 证书签发方和到期时间 |  |
| 日志留存期和转储目标 |  |
| 运维负责人、安全审批人 |  |
| 回滚包位置和回滚负责人 |  |
