# OpenResty 七层 WAF —— 运维交接说明（含对接 OpenClaw 剩余工作）

> 交接日期：2026-06-23　|　移交方：<填，OpenResty WAF 开发/部署方>　|　接收方：运维团队
>
> 配套文档（同仓库 `docs/`，本说明只做提要，细节查它们）：
> - `离线部署教程.md` —— 完整的离线安装 / 部署 / 启动 / 排障手册（命令级）
> - `WAF规则配置指南.md` —— 规则语义与配置写法
> - `流量安全网关方案-工作分析.md` —— 整体方案、P0–P7 阶段、风险与待澄清项

---

## 1. 移交对象与当前状态

| 项 | 值 |
|---|---|
| 服务器 | RHEL 8.10（el8），主机名 `AI-OpenClaw-B` |
| OpenResty | `1.31.1.1`，装于 `/usr/local/openresty/`（4 个自包含 RPM 离线安装） |
| 项目目录 | `/opt/openresty-waf`（属主 `root:nobody`，目录 750 / 文件 640 加固，`logs/` 归 `nobody` 可写） |
| 服务 | systemd 单元 `openresty-waf.service`，已 `enable --now`（开机自启 + 崩溃自拉起） |
| 监听 | `0.0.0.0:8080` |
| SELinux / firewalld | **Disabled / not running**（见 §4 注意事项） |
| 自检 | `scripts/smoke.sh` 9 条用例全绿 |
| 能力范围 | 方案 **P2（URL 黑白名单）+ P3（请求体 JSON 校验）**；尚未含 P4 客户端身份认证、P5 配置热更新中心等 |

> **⚠️ 重要：当前 `location /` 是测试桩。** 放行的流量只回 `{"ok":true,"upstream":"stub"}`，**尚未真正转发到 OpenClaw**。把桩换成真转发到 OpenClaw 是本次交接需要你们完成的核心剩余工作，见 **§3**。

WAF 在 `access_by_lua` 阶段的判定顺序（fail-closed）：
```
读请求头 → POST/PUT/PATCH 预处理：Content-Type 非 json→415；body 落盘→413；body 非法 JSON→400
  ↓ 进入决策链（按序短路）
① 头被截断→400 too_many_headers ；命中 forbidden_headers(x-openclaw-*)→403 forbidden_header
② 黑名单命中→403 blacklist
③ 不在白名单→403 not_in_whitelist（默认拒绝）
④ body schema 不过→400 / 422
通过 → 当前是 stub；接 OpenClaw 后 → proxy_pass 到上游
```

返回码语义、规则现状（白名单/黑名单/body 规则）见 `离线部署教程.md` §10。

---

## 2. 日常运维 runbook（细节见 `离线部署教程.md` §8 / §11 / §13）

统一用绝对路径，避免和系统里其它 nginx 混淆：
```bash
OR=/usr/local/openresty/bin/openresty
LUA=/usr/local/openresty/luajit/bin/luajit
P=/opt/openresty-waf/

systemctl status openresty-waf            # 查状态（active running 即正常）
systemctl reload  openresty-waf           # 改配置/规则后热加载（无中断）
systemctl restart openresty-waf           # 重启
journalctl -u openresty-waf -e            # 看启动失败原因

sudo $OR -p $P -c conf/nginx.conf -t      # 【改配置后必跑】语法 + Lua 加载预检
$LUA ${P}scripts/check_rules.lua          # 【改规则后必跑】规则体检
sudo bash ${P}scripts/smoke.sh            # 冒烟自检（文件 640，需 sudo 才能读脚本）
tail -f ${P}logs/error.log                # 运行日志，含每条 waf action=allow/deny ... reason=...
```

**改规则标准流程**（改 `conf/waf_rules.lua`，如加白名单 / 调上限 / 加黑名单）：
```
改 waf_rules.lua  →  check_rules.lua 体检  →  openresty -t 校验  →  systemctl reload
```
> 规则是 `init_by_lua` 静态加载，**坏规则会让整个进程起不来（fail-closed）**。务必先体检 + `-t` 校验通过再 `reload`，不要跳过。

升级 / 回滚流程见 `离线部署教程.md` §14（上线前 `cp -a` 备份 `conf/`、`lua/`，出问题原样拷回再 `reload`）。

---

## 3. 剩余工作：把测试桩切成转发到 OpenClaw（方案 §12 / P4-1）

分两步：**3A 需向相关方收齐的材料**（部分要找下列子团队索取），**3B 材料齐后在 WAF 上做的配置变更**。

### 3A. 需收齐的材料

> 这些是「物料 / 凭据」，不是能远程配进 WAF 的东西——地址/放通要在网络设备上做。按下表归口收集。
>
> **本方案不做 mTLS、不校验上游证书（`proxy_ssl_verify off`），因此无需任何证书（`ca/server/client`），OpenClaw 侧也无需信任配置。** 若日后安全基线要求验证上游身份，再按 §4 补 CA。

**A. 上游地址与网络连通（必需）**
- [ ] OpenClaw 对外服务的 `IP:端口`（或域名:端口）——要的是它**对外的 OpenAI 兼容接口地址**，不是本地控制面 `127.0.0.1:18789`。〔网络/基础设施〕
- [ ] 协议确认：上游为 **HTTPS**（本网关用 `proxy_pass https://`，但 `proxy_ssl_verify off` 不校验其证书）。〔OpenClaw 运维方〕
- [ ] 网络放通：在网络层放行 **本网关 IP → OpenClaw IP:端口** 的出方向（不放通会 502 / 超时）。〔网络/基础设施〕
- [ ] 是否多实例：单点还是多副本？多副本给全部 `IP:端口`（是否要负载/健康检查一并说）。〔OpenClaw 运维方〕
- [ ]（若用域名）本网关能否解析该域名——离线环境无公网 DNS，可能需写 `/etc/hosts` 或配内网 DNS。〔网络/基础设施〕

**B. 接入鉴权（是否要带 Token，必需确认）**
- [ ] 网关访问 OpenClaw 是否还要带 `Authorization: Bearer xxx` / API Key？要的话给值、头名，以及该 key 的管理/轮换归属（网关侧用 `proxy_set_header` 注入）。〔OpenClaw 运维方 / 应用方〕

**C. 接口契约（用于把规则从占位值收紧，建议一起要）**
- [ ] 真实对外开放的**路径白名单**（现占位仅 `POST /v1/chat/completions`、`GET /v1/models`）。〔应用方〕
- [ ] 允许的 **model 列表**（OpenClaw 形如 `openclaw/<agentId>`；当前规则占位 `openclaw` / `openclaw/default`，需实例实际 agent 列表）。〔应用方/运维〕
- [ ] 请求体真实上限：`messages` 条数、单条/累计长度、是否允许 `stream`、还允许哪些字段。〔应用方〕

**D. 联调协调（建议）**
- [ ] 约联调窗口：切 `proxy_pass` 要 `reload`，且需 OpenClaw 侧配合做端到端连通测试。
- [ ]（后续 P6）审计日志外发 SIEM 的接收地址/协议（syslog / HTTP）——现不阻塞。

### 3B. 材料齐后在 WAF 上做的配置变更

> 仓库 `conf/nginx.conf` 已是 `proxy_pass` + `proxy_ssl_verify off` 的无 mTLS 版（随包 `openresty-waf.tgz` 部署即生效），下面主要是**填地址 + 收紧规则 + 放行外联**。

1) 改 `conf/nginx.conf` 的 `upstream`：把占位地址换成材料 A 的真实 `IP:端口`。**完整模板见 `离线部署教程.md` §12**，要点：
```nginx
upstream openclaw_backend {
    server <OpenClaw_IP>:<端口>;     # 来自材料 A（不是控制面 127.0.0.1:18789）
    keepalive 16;
}
server {
    listen 8080;
    default_type application/json;
    location / {
        access_by_lua_block { require("waf.handler").access() }   # 保留 WAF 判定

        proxy_pass https://openclaw_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Connection "";
        # proxy_set_header Authorization "Bearer <token>";        # 若材料 B 需要

        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_ssl_verify off;     # 不做 mTLS，也不校验上游证书（内网简化）
    }
}
```

2) 按真实契约收紧 `conf/waf_rules.lua`（路径白名单 / model 列表 / 上限，来自材料 C）。

3) 放行 SELinux 外联（否则 `proxy_pass` 出方向被禁、502），校验并热加载：
```bash
sudo setsebool -P httpd_can_network_connect 1
/usr/local/openresty/luajit/bin/luajit /opt/openresty-waf/scripts/check_rules.lua
sudo /usr/local/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx.conf -t
sudo systemctl reload openresty-waf
```

4) 端到端验证：约 OpenClaw 侧联调，发一条真实 `POST /v1/chat/completions`，确认**透传到 OpenClaw 并拿到真实响应**（不再是 stub 的 `{"ok":true,"upstream":"stub"}`）。

---

## 4. 注意事项 / 风险

- **不校验上游证书**：当前 `proxy_ssl_verify off`，本网关不验证 OpenClaw 身份，理论上有中间人风险，内网可控环境通常可接受。**若日后要验证上游身份**：向 OpenClaw 要其服务端证书的 CA（`ca.crt`），改 `proxy_ssl_verify on` + `proxy_ssl_trusted_certificate <ca>` + `proxy_ssl_name <上游证书 CN/SAN>`，仍无需客户端证书（带 client 证书那才是 mTLS）。
- **SELinux 现为 Disabled**：若安全基线要求开回 Enforcing，先 `restorecon -Rv /opt/openresty-waf`，再 `semanage port -a -t http_port_t -p tcp 8080`；接 `proxy_pass` 后还需 `setsebool -P httpd_can_network_connect 1`，否则出方向被禁、502。详见 `离线部署教程.md` §7 / §12。
- **firewalld 现 not running**：8080 对外暴露由上层网络/安全组控制，按基线确认是否需收口。
- **改规则风险**：坏规则 fail-closed 会让进程起不来——改完务必先 `check_rules` + `-t` 再 `reload`。

---

## 5. 验收口径（当前已满足项）

`scripts/smoke.sh` 对 `http://127.0.0.1:8080` 的 9 条用例（移交时全绿）：

| 用例 | 期望码 |
|---|---|
| 合法 chat 请求（放行） | 200 |
| 白名单内 `GET /v1/models` | 200 |
| 未在白名单的路径（默认拒绝） | 403 |
| 黑名单 `/v1/admin` | 403 |
| `model` 不在允许列表 | 422 |
| 出现未知字段（additionalProperties） | 400 |
| `system` 不在首位（防伪 system 注入） | 422 |
| 非 `application/json` 的 POST | 415 |
| 带 `x-openclaw-model` 覆盖头（防 model 旁路） | 403 |

> 接 OpenClaw 后，放行用例的响应应变为 OpenClaw 的真实返回；拦截类用例码不变。建议把「端到端透传成功」补入验收清单。
