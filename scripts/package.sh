#!/usr/bin/env bash
# 在开发机(macOS)上,把「运行期需要的文件 + 部署辅助」打成一个干净 tar 包,
# 供离线拷贝到 CentOS 服务器。只携带指定运维文档，不含 spec/ Makefile/ .git/ .idea/
# 等开发期内容。
#
# 用法(在仓库根目录执行):
#   bash scripts/package.sh                 # 生成 openresty-waf.tgz
#   bash scripts/package.sh /tmp/waf.tgz    # 指定输出路径
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PKG_NAME="openresty-waf"        # 解包后的顶层目录名
OUT="${1:-$ROOT/openresty-waf.tgz}"

# 运行期 + 部署需要随包带上的文件(logs/ 不带,在服务器上现建)
FILES=(
  conf/nginx.conf
  conf/nginx-blue.conf.template
  conf/nginx-yellow.conf.template
  conf/waf-http-common.conf
  conf/waf-audit-log-format.conf
  conf/waf-audit-vars.conf
  conf/waf-public-location.conf
  conf/waf_rules.lua
  conf/waf_rules_knowledge_example.lua
  lua/waf/url_filter.lua
  lua/waf/json_validator.lua
  lua/waf/decision.lua
  lua/waf/factory.lua
  lua/waf/regex.lua
  lua/waf/handler.lua
  lua/waf/rules_lint.lua
  scripts/smoke.sh
  scripts/server-setup.sh
  scripts/check_rules.lua
  deploy/openresty-waf@.service
  docs/双WAF部署与运维交接手册.md
  docs/知识库接口文档.md
)

TMP="$(mktemp -d)"
STAGE="$TMP/$PKG_NAME"
mkdir -p "$STAGE"
for f in "${FILES[@]}"; do
  [ -f "$f" ] || { echo "缺少文件: $f" >&2; exit 1; }
  mkdir -p "$STAGE/$(dirname "$f")"
  cp "$f" "$STAGE/$f"
done

# 统一换行为 LF,去掉可能的 CRLF(避免在 CentOS 上脚本/配置被解析异常)
find "$STAGE" -type f \( -name '*.sh' -o -name '*.lua' -o -name '*.conf' -o -name '*.template' \
  -o -name '*.service' -o -name '*.json' -o -name '*.md' \) \
  -exec perl -pi -e 's/\r$//' {} +

# COPYFILE_DISABLE=1 阻止 macOS 往 tar 里塞 ._AppleDouble / 扩展属性条目
COPYFILE_DISABLE=1 tar -czf "$OUT" -C "$TMP" "$PKG_NAME"
rm -rf "$TMP"

echo "打包完成: $OUT"
echo "内容:"
tar -tzf "$OUT" | sed 's/^/  /'
