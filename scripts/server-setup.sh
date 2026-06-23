#!/usr/bin/env bash
# 在 CentOS 服务器上准备 WAF 运行环境:定位二进制、建 logs、设属主权限、做配置语法校验。
# SELinux / firewalld 这类要按现场策略拍板的操作,本脚本只「打印命令」不自动执行。
#
# 前提:已把项目解包到 $PREFIX(默认 /opt/openresty-waf),且服务器已装好 OpenResty。
# 用法:
#   sudo bash /opt/openresty-waf/scripts/server-setup.sh
#   # 可用环境变量覆盖默认值:
#   sudo PREFIX=/opt/openresty-waf RUN_USER=nobody PORT=8080 bash .../server-setup.sh
set -euo pipefail

PREFIX="${PREFIX:-/opt/openresty-waf}"
RUN_USER="${RUN_USER:-nobody}"
PORT="${PORT:-8080}"
OPENRESTY="${OPENRESTY:-/usr/local/openresty/bin/openresty}"

echo "== 1. 定位 openresty 二进制 =="
if [ ! -x "$OPENRESTY" ]; then
  OPENRESTY="$(command -v openresty || true)"
fi
if [ -z "${OPENRESTY:-}" ] || [ ! -x "$OPENRESTY" ]; then
  echo "找不到 openresty。请执行 'rpm -ql openresty | grep bin/openresty' 定位后用 OPENRESTY=... 重试。" >&2
  exit 1
fi
echo "  使用: $OPENRESTY"
"$OPENRESTY" -v 2>&1 || true

echo "== 2. 建 logs 目录并设属主/权限 =="
mkdir -p "$PREFIX/logs"
# 整体属主 root、属组运行用户;目录可进入、文件只读(防运行态被篡改)
chown -R "root:$RUN_USER" "$PREFIX"
find "$PREFIX" -type d -exec chmod 750 {} +
find "$PREFIX" -type f -exec chmod 640 {} +
# logs 必须让 worker(运行用户)可写,否则 error_log/access_log 写不进去
chown -R "$RUN_USER:$RUN_USER" "$PREFIX/logs"
chmod 770 "$PREFIX/logs"
echo "  $PREFIX 属主权限已设置,logs 归 $RUN_USER 可写"

echo "== 3. 配置语法校验 (openresty -t) =="
"$OPENRESTY" -p "$PREFIX/" -c conf/nginx.conf -t

cat <<EOF

== 基础准备完成。以下按现场状态「选做」(均需 root) ==

# (a) SELinux 是否 Enforcing:
getenforce

# 若为 Enforcing,放行 $PORT 端口绑定 + 修正 $PREFIX 文件上下文:
semanage port -a -t http_port_t -p tcp $PORT 2>/dev/null || semanage port -m -t http_port_t -p tcp $PORT
semanage fcontext -a -t httpd_sys_content_t "$PREFIX(/.*)?"
restorecon -Rv "$PREFIX"
#   (semanage 来自 policycoreutils-python-utils[C8]/policycoreutils-python[C7],缺则离线装该 RPM)
#   (将来接 proxy_pass 到上游 OpenClaw 时,还需放行出方向: setsebool -P httpd_can_network_connect 1)

# (b) firewalld 是否开启,需被其它主机访问时放行 $PORT:
firewall-cmd --permanent --add-port=$PORT/tcp && firewall-cmd --reload

# (c) 启动(命令行方式;生产建议改用 systemd,见 deploy/openresty-waf.service):
$OPENRESTY -p "$PREFIX/" -c conf/nginx.conf

# (d) 验证:
bash $PREFIX/scripts/smoke.sh
EOF
