-- V2 请求/响应决策链：请求头完整性 → host+method+path → Query/头/认证/正文/业务策略。
-- 纯逻辑，不依赖 ngx。
local RequestNormalizer = require("waf.request_normalizer")

local Decision = {}
Decision.__index = Decision

local function deny(status, reason, extra)
  local result = { action = "deny", status = status, reason = reason }
  for key, value in pairs(extra or {}) do result[key] = value end
  return result
end

function Decision.new(opts)
  opts = opts or {}
  return setmetatable({
    whitelist = opts.whitelist,
    validators = opts.validators or {},
    policy_engine = opts.policy_engine,
  }, Decision)
end

function Decision:match(req)
  if req.headers_truncated then return deny(400, "too_many_headers") end
  local headers, header_err = RequestNormalizer.normalize_headers(req.headers)
  if not headers then return deny(header_err.status, header_err.reason, { field = header_err.field }) end

  if req.raw_path ~= nil and req.raw_path ~= req.path then
    return deny(403, "non_canonical_path")
  end

  local rule, path_parameters
  if self.whitelist then
    rule, path_parameters = self.whitelist:match(req.host, req.method, req.path)
  end
  if not rule then return deny(403, "not_in_whitelist") end

  local request = rule.request or {}
  if (req.query_present or (req.args ~= nil and req.args ~= "")) and not request.query_schema then
    return deny(403, "query_not_allowed", { rule = rule })
  end
  if req.body_present and not request.body then
    return deny(400, "unexpected_body", { rule = rule })
  end
  return {
    action = "allow",
    status = 200,
    rule = rule,
    path_parameters = path_parameters or {},
    headers = headers,
  }
end

local function validation_denial(reason, err, rule)
  local status = err.code == "schema" and 400 or 422
  return deny(status, reason, { field = err.field, message = err.message, rule = rule })
end

function Decision:validate_request(rule, req)
  req = req or {}
  local request = rule.request or {}
  local body_policy = request.body
  if body_policy then
    if body_policy.required and not req.body_present then
      return deny(400, "request_body_required", { rule = rule })
    end
    if req.body_present and body_policy.schema then
      local validator = self.validators[body_policy.schema]
      if not validator then
        return deny(500, "misconfigured", { field = body_policy.schema, rule = rule })
      end
      local ok, err = validator:validate(req.body)
      if not ok then return validation_denial("request_body", err, rule) end
    end
  elseif req.body_present then
    return deny(400, "unexpected_body", { rule = rule })
  end

  if request.query_schema then
    local validator = self.validators[request.query_schema]
    if not validator then
      return deny(500, "misconfigured", { field = request.query_schema, rule = rule })
    end
    local ok, err = validator:validate(req.query or {})
    if not ok then return validation_denial("request_query", err, rule) end
  end

  if not self.policy_engine then
    return deny(500, "misconfigured", { field = "policy_engine", rule = rule })
  end
  local forward_headers, header_rejection = self.policy_engine:validate_headers(rule, req.headers or {})
  if not forward_headers then
    header_rejection.rule = rule
    header_rejection.action = "deny"
    return header_rejection
  end
  local policy_ok, policy_rejection = self.policy_engine:validate_request_policies(rule, req.body)
  if not policy_ok then
    policy_rejection.rule = rule
    policy_rejection.action = "deny"
    return policy_rejection
  end

  return {
    action = "allow",
    status = 200,
    rule = rule,
    forward_headers = forward_headers,
  }
end

function Decision:response_policy(rule, status)
  local policy = rule and rule.responses and rule.responses[status]
  if not policy then
    return nil, deny(502, "response_status_not_allowed", {
      field = tostring(status), rule = rule,
    })
  end
  return policy
end

function Decision:validate_response(rule, status, body)
  local policy, rejected = self:response_policy(rule, status)
  if not policy then return rejected end
  local body_policy = policy.body or {}
  if not body_policy.schema then
    return { action = "allow", status = status, rule = rule, policy = policy }
  end
  local validator = self.validators[body_policy.schema]
  if not validator then
    return deny(500, "misconfigured", { field = body_policy.schema, rule = rule })
  end
  local ok, err = validator:validate(body)
  if not ok then
    return deny(502, "response_body", {
      field = err.field, message = err.message, rule = rule, policy = policy,
    })
  end
  return { action = "allow", status = status, rule = rule, policy = policy }
end

function Decision:evaluate(req)
  local matched = self:match(req)
  if matched.action == "deny" then return matched end
  req.headers = matched.headers
  local result = self:validate_request(matched.rule, req)
  result.path_parameters = matched.path_parameters
  return result
end

return Decision
