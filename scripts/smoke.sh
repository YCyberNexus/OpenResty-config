#!/usr/bin/env bash
# 本地知识库规则示例的冒烟测试。生产 URL 由运维配置，需另编对应验收用例。
set -u
BASE="${BASE:-http://127.0.0.1:8080}"
fail=0

check() {
  local description="$1" expected="$2"
  shift 2
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' "$@")"
  if [[ "$code" == "$expected" ]]; then
    printf '  ✓ %-48s -> %s\n' "$description" "$code"
  else
    printf '  ✗ %-48s -> %s (expected %s)\n' "$description" "$code" "$expected"
    fail=1
  fi
}

echo "smoke against $BASE"
check "GET health: allow + validate response" 200 "$BASE/ai/knowledge/health"
check "POST search: allow + validate both bodies" 200 \
  -X POST "$BASE/ai/knowledge/search" \
  -H 'Content-Type: application/json' \
  -d '{"query":"机台发生通信异常时应该如何处理？","top_k":5}'
check "unlisted path: default deny" 403 "$BASE/ai/knowledge/export"
check "wrong method on listed path: default deny" 403 -X PUT "$BASE/ai/knowledge/health"
check "query string: deny" 403 "$BASE/ai/knowledge/health?debug=true"
check "top_k above 50: deny" 422 \
  -X POST "$BASE/ai/knowledge/search" -H 'Content-Type: application/json' \
  -d '{"query":"q","top_k":51}'
check "unknown request field: deny" 400 \
  -X POST "$BASE/ai/knowledge/search" -H 'Content-Type: application/json' \
  -d '{"query":"q","tenant":"unknown"}'
check "non-JSON content type: deny" 415 \
  -X POST "$BASE/ai/knowledge/search" -H 'Content-Type: text/plain' -d 'q'
check "method override header: deny" 403 \
  -X POST "$BASE/ai/knowledge/search" -H 'Content-Type: application/json' \
  -H 'X-HTTP-Method-Override: GET' -d '{"query":"q"}'
check "compressed request marker: deny" 403 \
  -X POST "$BASE/ai/knowledge/search" -H 'Content-Type: application/json' \
  -H 'Content-Encoding: gzip' -d '{"query":"q"}'

exit "$fail"
