-- OpenResty 请求/响应处理：Host 白名单、JSON schema 校验、规范化和审计。
-- 上游响应通过受限内部子请求完整取得；校验通过前不会向调用方发送响应正文。
local cjson = require("cjson.safe")
local factory = require("waf.factory")
local rules_lint = require("waf.rules_lint")
local has_resty_sha256, resty_sha256 = pcall(require, "resty.sha256")
local has_resty_string, resty_string = pcall(require, "resty.string")

local M = {}
local decision
local max_request_body_bytes = 16384
local max_response_body_bytes = 1048576
local INTERNAL_UPSTREAM_PREFIX = "/__waf_upstream"

-- 严格区分 JSON 空数组 [] 和空对象 {}，并限制解析深度与非法数字。
if type(cjson.decode_array_with_array_mt) == "function" then
  cjson.decode_array_with_array_mt(true)
end
if type(cjson.decode_max_depth) == "function" then cjson.decode_max_depth(32) end
if type(cjson.decode_invalid_numbers) == "function" then cjson.decode_invalid_numbers(false) end
if type(cjson.encode_invalid_numbers) == "function" then cjson.encode_invalid_numbers(false) end

local function set_var(name, value)
  pcall(function() ngx.var[name] = tostring(value == nil and "-" or value) end)
end

local function to_hex(value)
  return (value:gsub(".", function(char) return string.format("%02x", string.byte(char)) end))
end

local function sha256(value)
  if type(value) ~= "string" then return "-" end
  if has_resty_sha256 and has_resty_string then
    local digest = resty_sha256:new()
    if digest and digest:update(value) then
      local value_bin = digest:final()
      if value_bin then return resty_string.to_hex(value_bin) end
    end
  end
  if type(ngx.sha256_bin) ~= "function" then return "unavailable" end
  return to_hex(ngx.sha256_bin(value))
end

local function read_body_file(path)
  if type(path) ~= "string" or path == "" then return nil end
  local file = io.open(path, "rb")
  if not file then return nil end
  local body = file:read("*a")
  file:close()
  return body
end

local function request_id()
  local trace = ngx.var.waf_trace_id
  if trace and trace ~= "" and trace ~= "-" then return trace end
  return ngx.var.request_id
end

local function apply_decision(result, action)
  set_var("waf_action", action or result.action or "-")
  set_var("waf_reason", result.reason or "-")
  set_var("waf_field", result.field or "-")
  set_var("waf_rule_id", result.rule and result.rule.id or "-")
end

local function write_json(status, payload)
  local encoded = cjson.encode(payload)
  if not encoded then
    status = 500
    encoded = '{"error":"response_encoding_failed"}'
  end
  set_var("waf_forward_response_body", encoded)
  set_var("waf_forward_response_bytes", #encoded)
  set_var("waf_forward_response_sha256", sha256(encoded))
  ngx.status = status
  ngx.header.content_type = "application/json"
  ngx.header.content_length = #encoded
  ngx.print(encoded)
  return ngx.exit(status)
end

local function deny_request(result)
  apply_decision(result, "deny_request")
  return write_json(result.status, {
    error = result.reason,
    field = result.field,
    request_id = request_id(),
  })
end

local function deny_response(result)
  apply_decision(result, "deny_response")
  if result.policy and result.policy.schema then
    set_var("waf_response_schema", result.policy.schema)
  end
  return write_json(result.status or 502, {
    error = result.reason or "upstream_response_rejected",
    field = result.field,
    request_id = request_id(),
  })
end

local function is_json_media_type(content_type)
  if type(content_type) ~= "string" then return false end
  local media_type = content_type:lower():match("^%s*([^;]+)")
  if not media_type then return false end
  media_type = media_type:match("^(.-)%s*$")
  return media_type == "application/json"
end

local function has_body_header(headers)
  local content_length = headers and (headers["content-length"] or headers["Content-Length"])
  if type(content_length) == "table" then content_length = content_length[1] end
  if tonumber(content_length or "0") > 0 then return true end
  local transfer_encoding = headers and (headers["transfer-encoding"] or headers["Transfer-Encoding"])
  return transfer_encoding ~= nil and transfer_encoding ~= ""
end

local function response_header(headers, wanted)
  local found
  for key, value in pairs(headers or {}) do
    if tostring(key):lower() == wanted then
      if found ~= nil or type(value) == "table" then return nil, "duplicate" end
      found = value
    end
  end
  return found
end

local function capture_method(method)
  return ngx["HTTP_" .. tostring(method or "")]
end

local function reset_request_state()
  set_var("waf_action", "unprocessed")
  set_var("waf_reason", "-")
  set_var("waf_field", "-")
  set_var("waf_rule_id", "-")
  set_var("waf_request_host", "-")
  set_var("waf_request_body", "")
  set_var("waf_request_body_bytes", 0)
  set_var("waf_request_body_sha256", "-")
  set_var("waf_forward_body", "")
  set_var("waf_forward_body_bytes", 0)
  set_var("waf_forward_body_sha256", "-")
  set_var("waf_upstream_addr", "-")
  set_var("waf_upstream_status", "-")
  set_var("waf_response_schema", "-")
  set_var("waf_response_body", "")
  set_var("waf_response_body_bytes", 0)
  set_var("waf_response_body_sha256", "-")
  set_var("waf_forward_response_body", "")
  set_var("waf_forward_response_bytes", 0)
  set_var("waf_forward_response_sha256", "-")
end

function M.init(config)
  config = config or {}
  local issues = rules_lint.lint(config)
  if rules_lint.count(issues, "error") > 0 then
    local first
    for _, issue in ipairs(issues) do
      if issue.level == "error" then first = issue break end
    end
    error("waf.handler: invalid rules at " .. tostring(first and first.where or "unknown")
      .. ": " .. tostring(first and first.msg or "validation failed"))
  end
  decision = factory.build_decision(config, {
    null_value = cjson.null,
    array_mt = cjson.array_mt,
  })
  max_request_body_bytes = config.max_request_body_bytes or 16384
  max_response_body_bytes = config.max_response_body_bytes or 1048576
end

function M.access()
  reset_request_state()
  ngx.ctx = ngx.ctx or {}

  local host = ngx.var.host
  local method = ngx.req.get_method()
  local path = ngx.var.uri
  local request_uri = ngx.var.request_uri
  local raw_path = type(request_uri) == "string" and request_uri:match("^([^?]*)") or nil
  local headers, headers_err = ngx.req.get_headers()
  ngx.req.read_body()
  local request_body_file = ngx.req.get_body_file()
  local raw_request_body = ngx.req.get_body_data()
  if raw_request_body == nil and request_body_file ~= nil then
    raw_request_body = read_body_file(request_body_file)
  end
  if raw_request_body ~= nil then
    set_var("waf_request_body", raw_request_body)
    set_var("waf_request_body_bytes", #raw_request_body)
    set_var("waf_request_body_sha256", sha256(raw_request_body))
  end
  local precheck = decision:match({
    host = host,
    method = method,
    path = path,
    raw_path = raw_path,
    args = ngx.var.args,
    query_present = ngx.var.is_args == "?"
      or (type(request_uri) == "string" and request_uri:find("?", 1, true) ~= nil),
    headers = headers,
    headers_truncated = headers_err == "truncated",
    body_present = has_body_header(headers),
  })
  if precheck.action == "deny" then return deny_request(precheck) end

  local rule = precheck.rule
  local normalized
  set_var("waf_rule_id", rule.id)
  set_var("waf_request_host", host)
  if rule.request_schema then
    if not is_json_media_type(ngx.var.content_type) then
      return deny_request({
        action = "deny", status = 415, reason = "unsupported_media_type", rule = rule,
      })
    end
    local raw = raw_request_body
    if request_body_file ~= nil then
      return deny_request({
        action = "deny", status = 413, reason = "request_body_too_large", rule = rule,
      })
    end
    if raw ~= nil then
      if #raw > max_request_body_bytes then
        return deny_request({
          action = "deny", status = 413, reason = "request_body_too_large", rule = rule,
        })
      end
    end

    local body = raw ~= nil and cjson.decode(raw) or nil
    if body == nil then
      return deny_request({ action = "deny", status = 400, reason = "invalid_json", rule = rule })
    end
    local validated = decision:validate_request(rule, body)
    if validated.action == "deny" then return deny_request(validated) end

    -- 只转发 WAF 已解析并重新编码的单一 JSON 语义。
    normalized = cjson.encode(body)
    if normalized == nil then
      return deny_request({
        action = "deny", status = 500, reason = "request_normalization_failed", rule = rule,
      })
    end
    if #normalized > max_request_body_bytes then
      return deny_request({
        action = "deny", status = 413, reason = "request_body_too_large", rule = rule,
      })
    end
    ngx.req.set_body_data(normalized)
    set_var("waf_forward_body", normalized)
    set_var("waf_forward_body_bytes", #normalized)
    set_var("waf_forward_body_sha256", sha256(normalized))
  else
    -- 无 request_schema 的白名单接口一律不允许正文。
    local unexpected = raw_request_body
    local unexpected_file = request_body_file
    if (unexpected ~= nil and #unexpected > 0) or unexpected_file ~= nil then
      return deny_request({
        action = "deny", status = 400, reason = "unexpected_body", rule = rule,
      })
    end
  end

  ngx.ctx.waf_rule = rule
  ngx.ctx.waf_method = method
  ngx.ctx.waf_path = path
  ngx.ctx.waf_forward_body = normalized
  apply_decision({ action = "allow", rule = rule }, "allow_request")
end

function M.proxy()
  local ctx = ngx.ctx or {}
  local rule = ctx.waf_rule
  if not rule then
    return deny_response({ status = 500, reason = "request_context_missing" })
  end
  if not ngx.location or type(ngx.location.capture) ~= "function" then
    return deny_response({ status = 500, reason = "response_capture_unavailable", rule = rule })
  end

  local method = capture_method(ctx.waf_method)
  if method == nil then
    return deny_response({ status = 500, reason = "unsupported_proxy_method", rule = rule })
  end
  if type(ctx.waf_path) ~= "string" or ctx.waf_path:sub(1, 1) ~= "/" then
    return deny_response({ status = 500, reason = "request_context_missing", rule = rule })
  end

  -- 正文直接附着到子请求；Content-Length 由 Nginx 根据实际正文重新生成。
  local capture_opts = { method = method }
  if ctx.waf_forward_body ~= nil then capture_opts.body = ctx.waf_forward_body end

  local capture_ok, response = pcall(
    ngx.location.capture, INTERNAL_UPSTREAM_PREFIX .. ctx.waf_path, capture_opts
  )
  if not capture_ok or type(response) ~= "table" or type(response.status) ~= "number" then
    return deny_response({ status = 502, reason = "upstream_capture_failed", rule = rule })
  end

  local upstream_addr = response_header(response.header, "x-waf-internal-upstream-addr")
  set_var("waf_upstream_addr", upstream_addr or "-")
  set_var("waf_upstream_status", response.status)

  local raw = type(response.body) == "string" and response.body or ""
  set_var("waf_response_body", raw)
  set_var("waf_response_body_bytes", #raw)
  set_var("waf_response_body_sha256", sha256(raw))
  if response.truncated then
    return deny_response({ status = 502, reason = "response_body_too_large", rule = rule })
  end

  local policy, policy_rejection = decision:response_policy(rule, response.status)
  if not policy then return deny_response(policy_rejection) end
  set_var("waf_response_schema", policy.schema)
  if #raw > max_response_body_bytes or #raw > policy.max_body_bytes then
    return deny_response({
      status = 502, reason = "response_body_too_large", rule = rule, policy = policy,
    })
  end

  local content_type, content_type_err = response_header(response.header, "content-type")
  if content_type_err then
    return deny_response({
      status = 502, reason = "duplicate_upstream_header", field = "content-type",
      rule = rule, policy = policy,
    })
  end
  if not is_json_media_type(content_type) then
    return deny_response({
      status = 502, reason = "response_unsupported_media_type", field = "content-type",
      rule = rule, policy = policy,
    })
  end

  local content_encoding, content_encoding_err = response_header(response.header, "content-encoding")
  if content_encoding_err then
    return deny_response({
      status = 502, reason = "duplicate_upstream_header", field = "content-encoding",
      rule = rule, policy = policy,
    })
  end
  if type(content_encoding) == "string" and content_encoding ~= ""
    and content_encoding:lower() ~= "identity" then
    return deny_response({
      status = 502, reason = "response_content_encoding_not_allowed", field = "content-encoding",
      rule = rule, policy = policy,
    })
  end

  local body = cjson.decode(raw)
  if body == nil then
    return deny_response({
      status = 502, reason = "invalid_upstream_json", rule = rule, policy = policy,
    })
  end
  local validated = decision:validate_response(rule, response.status, body)
  if validated.action == "deny" then return deny_response(validated) end

  local normalized = cjson.encode(body)
  if normalized == nil then
    return deny_response({
      status = 502, reason = "response_normalization_failed", rule = rule, policy = policy,
    })
  end
  if #normalized > max_response_body_bytes or #normalized > policy.max_body_bytes then
    return deny_response({
      status = 502, reason = "response_body_too_large", rule = rule, policy = policy,
    })
  end

  set_var("waf_forward_response_body", normalized)
  set_var("waf_forward_response_bytes", #normalized)
  set_var("waf_forward_response_sha256", sha256(normalized))
  apply_decision({ action = "allow", rule = rule }, "allow_response")
  ngx.status = response.status
  ngx.header.content_type = "application/json"
  ngx.header.content_length = #normalized
  ngx.print(normalized)
  return ngx.exit(response.status)
end

return M
