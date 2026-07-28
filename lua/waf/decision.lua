-- 请求决策链：请求头完整性 → method+path 白名单 → 查询串 → 请求 schema。
-- 纯逻辑，不依赖 ngx。
local Decision = {}
Decision.__index = Decision

local function deny(status, reason, extra)
  local result = { action = "deny", status = status, reason = reason }
  if extra then
    for key, value in pairs(extra) do result[key] = value end
  end
  return result
end

local function norm_header(key)
  return tostring(key):lower():gsub("_", "-")
end

function Decision.new(opts)
  opts = opts or {}
  return setmetatable({
    whitelist = opts.whitelist,
    validators = opts.validators or {},
  }, Decision)
end

function Decision:match(req)
  if req.headers_truncated then return deny(400, "too_many_headers") end
  for key, value in pairs(req.headers or {}) do
    if type(value) == "table" then
      return deny(400, "duplicate_header", { field = norm_header(key) })
    end
  end

  local rule = self.whitelist and self.whitelist:match(req.method, req.path)
  if not rule then return deny(403, "not_in_whitelist") end

  if req.query_present or (req.args ~= nil and req.args ~= "") then
    return deny(403, "query_not_allowed", { rule = rule })
  end
  if req.body_present and not rule.request_schema then
    return deny(400, "unexpected_body", { rule = rule })
  end
  return { action = "allow", status = 200, rule = rule }
end

function Decision:validate_request(rule, body)
  if not rule.request_schema then return { action = "allow", status = 200, rule = rule } end
  local validator = self.validators[rule.request_schema]
  if not validator then
    return deny(500, "misconfigured", { field = rule.request_schema, rule = rule })
  end
  local ok, err = validator:validate(body, { phase = "request", rule = rule })
  if not ok then
    local status = err.code == "schema" and 400 or 422
    return deny(status, "request_body", { field = err.field, message = err.message, rule = rule })
  end
  return { action = "allow", status = 200, rule = rule }
end

function Decision:evaluate(req)
  local matched = self:match(req)
  if matched.action == "deny" then return matched end
  return self:validate_request(matched.rule, req.body)
end

return Decision
