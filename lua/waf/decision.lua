-- 决策链：先黑后白 + 默认拒绝（fail-closed）。
-- 组合 url_filter（黑/白名单）与 body_validator，给出最终放行/拒绝判定。
-- 纯逻辑，不依赖 ngx。
-- evaluate(req{method, path, body}) -> { action="allow"|"deny", status, reason, ... }
local Decision = {}
Decision.__index = Decision

function Decision.new(opts)
  opts = opts or {}
  return setmetatable({
    whitelist = opts.whitelist,
    blacklist = opts.blacklist,
    validators = opts.validators or {},
  }, Decision)
end

local function deny(status, reason, extra)
  local r = { action = "deny", status = status, reason = reason }
  if extra then
    for k, v in pairs(extra) do r[k] = v end
  end
  return r
end

function Decision:evaluate(req)
  -- ① 先过黑名单：命中即拒，避免白名单 URL 上夹带攻击 payload 被放行
  if self.blacklist and self.blacklist:match(req.method, req.path) then
    return deny(403, "blacklist")
  end

  -- ② 再过白名单：未命中一律拒绝（默认拒绝 / fail-closed）
  local rule = self.whitelist:match(req.method, req.path)
  if not rule then
    return deny(403, "not_in_whitelist")
  end

  -- ③ 命中规则若声明了 body schema，则做 body 校验
  if rule.body then
    local validator = self.validators[rule.body]
    if not validator then
      return deny(500, "misconfigured", { field = rule.body })
    end
    local ok, err = validator:validate(req.body)
    if not ok then
      local status = (err.code == "schema") and 400 or 422
      return deny(status, "body", { field = err.field, message = err.message })
    end
  end

  return { action = "allow", status = 200, rule = rule }
end

return Decision
