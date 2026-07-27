-- 决策链：来源 Host/请求头 → 黑名单 → URL 白名单 → 查询串 → 请求 schema。
-- 响应侧按“接口规则 + HTTP 状态码”选择 schema，未登记状态或校验失败一律拦截。
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

local function to_host_set(hosts)
  local result = {}
  for _, host in ipairs(hosts or {}) do result[tostring(host):lower()] = true end
  return result
end

function Decision.new(opts)
  opts = opts or {}
  local forbidden = {}
  for _, header in ipairs(opts.forbidden_headers or {}) do
    local name = tostring(header):lower()
    if name:sub(-1) == "*" then
      local prefix = name:sub(1, -2)
      if prefix ~= "" then forbidden[#forbidden + 1] = { prefix = prefix } end
    elseif name ~= "" then
      forbidden[#forbidden + 1] = { exact = name }
    end
  end
  return setmetatable({
    whitelist = opts.whitelist,
    blacklist = opts.blacklist,
    validators = opts.validators or {},
    forbidden_headers = forbidden,
    allowed_hosts = to_host_set(opts.allowed_hosts),
  }, Decision)
end

function Decision:match(req)
  if next(self.allowed_hosts) == nil then
    return deny(500, "misconfigured", { field = "allowed_hosts" })
  end
  if not self.allowed_hosts[tostring(req.host or ""):lower()] then
    return deny(403, "host_not_allowed")
  end

  if req.headers_truncated then return deny(400, "too_many_headers") end
  if req.headers then
    for key, value in pairs(req.headers) do
      local normalized = norm_header(key)
      if type(value) == "table" then
        return deny(400, "duplicate_header", { field = normalized })
      end
      for _, forbidden in ipairs(self.forbidden_headers) do
        if (forbidden.exact and normalized == forbidden.exact)
          or (forbidden.prefix and normalized:sub(1, #forbidden.prefix) == forbidden.prefix) then
          return deny(403, "forbidden_header", { field = normalized })
        end
      end
    end
  end

  if self.blacklist and self.blacklist:match(req.method, req.path) then
    return deny(403, "blacklist")
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

function Decision:validate_response(rule, status, body, request_body)
  local response_schemas = rule and rule.response_schemas or nil
  local schema_name = response_schemas and response_schemas[tostring(status)] or nil
  if not schema_name then
    return deny(502, "response_status_not_allowed", { field = tostring(status), rule = rule })
  end
  local validator = self.validators[schema_name]
  if not validator then
    return deny(502, "misconfigured", { field = schema_name, rule = rule })
  end
  local ok, err = validator:validate(body, {
    phase = "response",
    rule = rule,
    status = status,
    request_body = request_body,
  })
  if not ok then
    return deny(502, "response_body", { field = err.field, message = err.message, rule = rule })
  end
  return { action = "allow", status = status, rule = rule }
end

return Decision
