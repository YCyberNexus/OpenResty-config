-- V2 可复用认证门禁、请求头白名单和内置业务策略。
local JsonValidator = require("waf.json_validator")

local PolicyEngine = {}
PolicyEngine.__index = PolicyEngine

local function deny(status, reason, field)
  return nil, { status = status, reason = reason, field = field }
end

function PolicyEngine.new(config, opts)
  opts = opts or {}
  return setmetatable({
    config = config or {},
    validator_opts = {
      null_value = opts.null_value,
      array_mt = opts.array_mt,
    },
  }, PolicyEngine)
end

local function credential_valid(policy, value)
  if type(value) ~= "string" or value == "" or #value > (policy.max_bytes or 4096) then
    return false
  end
  if policy.mode == "bearer" then
    return value:match("^Bearer [A-Za-z0-9%-%._~%+/]+=*$") ~= nil
  end
  if policy.mode == "basic" then
    return value:match("^Basic [A-Za-z0-9+/]+=*$") ~= nil
  end
  if policy.mode == "api_key" then
    return value:match("^[!-~]+$") ~= nil
  end
  return false
end

function PolicyEngine:validate_headers(rule, headers)
  local forward = {}
  local request = rule.request or {}
  for name, policy in pairs(request.headers or {}) do
    local value = headers[name]
    if value == nil then
      if policy.required then return deny(400, "required_header_missing", name) end
    else
      local validator = JsonValidator.new(policy.schema, self.validator_opts)
      local ok, err = validator:validate(value)
      if not ok then return deny(400, "request_header", name .. ":" .. tostring(err.field)) end
      forward[name] = value
    end
  end

  local auth = self.config.auth and self.config.auth[rule.auth_policy]
  if not auth then return deny(500, "misconfigured", "auth_policy") end
  if auth.mode ~= "none" then
    local value = headers[auth.header]
    if value == nil then return deny(401, "credential_required", auth.header) end
    if not credential_valid(auth, value) then
      return deny(401, "credential_format", auth.header)
    end
    forward[auth.header] = value
  end
  return forward
end

local function cypher_tokens(value)
  if type(value) ~= "string" then return nil end
  local tokens, i, size = {}, 1, #value
  while i <= size do
    local char, next_char = value:sub(i, i), value:sub(i + 1, i + 1)
    if char:match("%s") then
      i = i + 1
    elseif char == "/" and next_char == "/" then
      local newline = value:find("\n", i + 2, true)
      i = newline and newline + 1 or size + 1
    elseif char == "/" and next_char == "*" then
      local ending = value:find("*/", i + 2, true)
      if not ending then return nil end
      i = ending + 2
    elseif char == "'" or char == '"' then
      local quote = char
      i = i + 1
      local closed = false
      while i <= size do
        char = value:sub(i, i)
        if char == "\\" then
          i = i + 2
        elseif char == quote then
          if value:sub(i + 1, i + 1) == quote then
            i = i + 2
          else
            i = i + 1
            closed = true
            break
          end
        else
          i = i + 1
        end
      end
      if not closed then return nil end
    elseif char == "`" then
      i = i + 1
      local closed = false
      while i <= size do
        if value:sub(i, i) == "`" then
          if value:sub(i + 1, i + 1) == "`" then
            i = i + 2
          else
            i = i + 1
            closed = true
            break
          end
        else
          i = i + 1
        end
      end
      if not closed then return nil end
    elseif char == ";" then
      return nil
    elseif char:match("[A-Za-z_]") then
      local ending = i
      while ending <= size and value:sub(ending, ending):match("[A-Za-z0-9_]") do
        ending = ending + 1
      end
      tokens[#tokens + 1] = value:sub(i, ending - 1):upper()
      i = ending
    else
      i = i + 1
    end
  end
  return tokens
end

local CYPHER_MUTATING = {
  CREATE = true, MERGE = true, DELETE = true, DETACH = true, SET = true,
  REMOVE = true, DROP = true, FOREACH = true, LOAD = true, CALL = true,
  GRANT = true, DENY = true, REVOKE = true, ALTER = true, RENAME = true,
  START = true, STOP = true, TERMINATE = true,
}
local CYPHER_READ_START = {
  MATCH = true, OPTIONAL = true, UNWIND = true, WITH = true, RETURN = true,
}

local function cypher_is_read_only(value)
  local tokens = cypher_tokens(value)
  if not tokens or not tokens[1] then return false end
  local first = 1
  if tokens[first] == "EXPLAIN" or tokens[first] == "PROFILE" then first = first + 1 end
  if not CYPHER_READ_START[tokens[first]] then return false end
  for _, token in ipairs(tokens) do
    if CYPHER_MUTATING[token] then return false end
  end
  return true
end

function PolicyEngine:validate_request_policies(rule, body)
  local names = rule.request and rule.request.policies or {}
  for _, name in ipairs(names) do
    local policy = self.config.request_policies and self.config.request_policies[name]
    if not policy then return deny(500, "misconfigured", name) end
    if policy.kind == "cypher_read_only" then
      local value = type(body) == "table" and body[policy.field] or nil
      if not cypher_is_read_only(value) then
        return deny(422, "request_policy", policy.field)
      end
    else
      return deny(500, "misconfigured", name)
    end
  end
  return true
end

PolicyEngine.cypher_is_read_only = cypher_is_read_only

return PolicyEngine
