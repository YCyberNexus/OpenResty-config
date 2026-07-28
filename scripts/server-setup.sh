#!/usr/bin/env bash
# 准备单个 WAF 节点。只创建目录/权限并校验已渲染配置，不替用户猜测地址或端口。
# 用法：sudo NODE_ROLE=blue bash /opt/openresty-waf/scripts/server-setup.sh
#       sudo NODE_ROLE=yellow bash /opt/openresty-waf/scripts/server-setup.sh
set -euo pipefail

PREFIX="${PREFIX:-/opt/openresty-waf}"
RUN_GROUP="${RUN_GROUP:-nobody}"
OPENRESTY="${OPENRESTY:-/data/openresty/bin/openresty}"
LUAJIT="${LUAJIT:-/data/openresty/luajit/bin/luajit}"
NODE_ROLE="${NODE_ROLE:-}"
DATA_ROOT="${DATA_ROOT:-/data/openresty-waf}"

if [[ "$NODE_ROLE" != "blue" && "$NODE_ROLE" != "yellow" ]]; then
  echo "NODE_ROLE 必须显式设为 blue 或 yellow。" >&2
  exit 2
fi

if [[ ! -x "$OPENRESTY" ]]; then
  OPENRESTY="$(command -v openresty || true)"
fi
if [[ -z "${OPENRESTY:-}" || ! -x "$OPENRESTY" ]]; then
  echo "找不到 openresty；请通过 OPENRESTY=/绝对路径 指定。" >&2
  exit 1
fi
if [[ ! -x "$LUAJIT" ]]; then
  LUAJIT="$(command -v luajit || true)"
fi
if [[ -z "${LUAJIT:-}" || ! -x "$LUAJIT" ]]; then
  echo "找不到 luajit；请通过 LUAJIT=/绝对路径 指定。" >&2
  exit 1
fi

CONFIG="$PREFIX/conf/nginx-$NODE_ROLE.conf"
TEMPLATE="$PREFIX/conf/nginx-$NODE_ROLE.conf.template"
if [[ ! -f "$CONFIG" ]]; then
  echo "缺少已渲染配置：$CONFIG" >&2
  echo "请从 $TEMPLATE 复制，按审批台账替换全部 __PLACEHOLDER__ 后重试。" >&2
  exit 2
fi
if grep -Eq '__[A-Z0-9_]+__' "$CONFIG"; then
  echo "$CONFIG 仍含未替换占位符，拒绝继续：" >&2
  grep -En '__[A-Z0-9_]+__' "$CONFIG" >&2
  exit 2
fi

echo "== 1. 准备持久化审计目录 =="
install -d -o root -g "$RUN_GROUP" -m 0750 "$DATA_ROOT/audit"
install -d -o root -g "$RUN_GROUP" -m 0750 "$DATA_ROOT/log"
for log_file in "$DATA_ROOT/audit/access.log" "$DATA_ROOT/audit/rejected.log" \
  "$DATA_ROOT/log/error.log"; do
  if [[ ! -e "$log_file" ]]; then
    install -o root -g "$RUN_GROUP" -m 0640 /dev/null "$log_file"
  else
    chown "root:$RUN_GROUP" "$log_file"
    chmod 0640 "$log_file"
  fi
done
echo "  审计：$DATA_ROOT/audit/access.log"
echo "  运行日志：$DATA_ROOT/log/error.log"

echo "== 2. 加固程序权限 =="
chown -R "root:$RUN_GROUP" "$PREFIX"
find "$PREFIX" -type d -exec chmod 0750 {} +
find "$PREFIX" -type f -exec chmod 0640 {} +

echo "== 3. 规则与 nginx 配置校验 =="
"$LUAJIT" "${PREFIX}/scripts/check_rules.lua" "${PREFIX}/conf/waf_rules.lua"
echo "  活动规则 SHA-256：$(sha256sum "${PREFIX}/conf/waf_rules.lua" | awk '{print $1}')"
"$OPENRESTY" -p "$PREFIX/" -c "conf/nginx-$NODE_ROLE.conf" -t

cat <<EOF

基础准备完成。启用前仍需按现场状态完成：

1. SELinux Enforcing：
   semanage fcontext -a -t httpd_sys_content_t "$PREFIX(/.*)?"
   semanage fcontext -a -t httpd_log_t "$DATA_ROOT(/.*)?"
   restorecon -Rv "$PREFIX" "$DATA_ROOT"
   setsebool -P httpd_can_network_connect 1
   并按审批端口配置 http_port_t（接口文档没有端口，本脚本不代填）。

2. 核对四层策略只允许已登记的源、目标 IP 和端口：蓝区业务 -> 蓝 WAF；
   蓝 WAF -> 黄 WAF；黄 WAF -> 已登记目标服务。蓝、黄两侧 conf/waf_rules.lua
   必须完全相同并具有相同 SHA-256。

3. 安装并启动实例服务：
   cp "$PREFIX/deploy/openresty-waf@.service" /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now "openresty-waf@$NODE_ROLE"

4. 用真实放行/拒绝用例核对 $DATA_ROOT/audit/access.log；配置日志轮转、留存期和防篡改转储。
EOF
