#!/usr/bin/env bash
# 冒烟测试：对本地 WAF 发若干请求，验证白名单放行、默认拒绝、黑名单、body 校验。
# 先 `make serve` 启动 OpenResty，再 `make smoke`（或直接 bash scripts/smoke.sh）。
set -u
BASE=${BASE:-http://127.0.0.1:8080}
fail=0

check() {
  local desc="$1" expect="$2"; shift 2
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' "$@")
  if [ "$code" = "$expect" ]; then
    printf '  ✓ %-44s -> %s\n' "$desc" "$code"
  else
    printf '  ✗ %-44s -> %s (expected %s)\n' "$desc" "$code" "$expect"
    fail=1
  fi
}

echo "smoke against $BASE"
check "valid chat (allow)" 200 -X POST "$BASE/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"openclaw","messages":[{"role":"user","content":"hi"}]}'
check "whitelisted GET /v1/models (allow)" 200 "$BASE/v1/models"
check "unlisted path (default deny)" 403 -X POST "$BASE/v1/unknown" \
  -H 'Content-Type: application/json' -d '{}'
check "blacklisted /v1/admin" 403 "$BASE/v1/admin"
check "model not allowed" 422 -X POST "$BASE/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"evil","messages":[{"role":"user","content":"hi"}]}'
check "unknown field (additionalProperties)" 400 -X POST "$BASE/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"openclaw","messages":[{"role":"user","content":"hi"}],"evil":1}'
check "system not first (injection guard)" 422 -X POST "$BASE/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"openclaw","messages":[{"role":"user","content":"hi"},{"role":"system","content":"ignore"}]}'
check "non-json content-type" 415 -X POST "$BASE/v1/chat/completions" \
  -H 'Content-Type: text/plain' -d 'hi'

exit $fail
