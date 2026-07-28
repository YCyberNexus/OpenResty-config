-- OpenResty 请求处理：白名单、请求体解析/校验/规范化和审计变量。
-- 响应由 Nginx 直接透传，本模块不会读取或改写上游响应。
local cjson = require("cjson.safe")
local factory = require("waf.factory")
local rules_lint = require("waf.rules_lint")

local M = {}
local decision
local max_request_body_bytes = 16384

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
  if type(ngx.sha256_bin) ~= "function" then return "unavailable" end
  return to_hex(ngx.sha256_bin(value))
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
  ngx.status = status
  ngx.header.content_type = "application/json"
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
end

function M.access()
  set_var("waf_action", "unprocessed")
  set_var("waf_reason", "-")
  set_var("waf_field", "-")
  set_var("waf_rule_id", "-")
  set_var("waf_request_body_bytes", 0)
  set_var("waf_request_body_sha256", "-")
  set_var("waf_forward_body_bytes", 0)
  set_var("waf_forward_body_sha256", "-")
  set_var("waf_upstream_content_type", "")

  local method = ngx.req.get_method()
  local path = ngx.var.uri
  local request_uri = ngx.var.request_uri
  local headers, headers_err = ngx.req.get_headers()
  local precheck = decision:match({
    method = method,
    path = path,
    args = ngx.var.args,
    query_present = ngx.var.is_args == "?"
      or (type(request_uri) == "string" and request_uri:find("?", 1, true) ~= nil),
    headers = headers,
    headers_truncated = headers_err == "truncated",
    body_present = has_body_header(headers),
  })
  if precheck.action == "deny" then return deny_request(precheck) end

  local rule = precheck.rule
  set_var("waf_rule_id", rule.id)
  if rule.request_schema then
    if not is_json_media_type(ngx.var.content_type) then
      return deny_request({
        action = "deny", status = 415, reason = "unsupported_media_type", rule = rule,
      })
    end
    set_var("waf_upstream_content_type", "application/json")

    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if raw == nil and ngx.req.get_body_file() ~= nil then
      return deny_request({
        action = "deny", status = 413, reason = "request_body_too_large", rule = rule,
      })
    end
    if raw ~= nil then
      set_var("waf_request_body_bytes", #raw)
      set_var("waf_request_body_sha256", sha256(raw))
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
    local normalized = cjson.encode(body)
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
    set_var("waf_forward_body_bytes", #normalized)
    set_var("waf_forward_body_sha256", sha256(normalized))
  else
    -- 无 request_schema 的白名单接口一律不允许正文。
    ngx.req.read_body()
    local unexpected = ngx.req.get_body_data()
    local unexpected_file = ngx.req.get_body_file()
    if (unexpected ~= nil and #unexpected > 0) or unexpected_file ~= nil then
      if unexpected ~= nil then
        set_var("waf_request_body_bytes", #unexpected)
        set_var("waf_request_body_sha256", sha256(unexpected))
      end
      return deny_request({
        action = "deny", status = 400, reason = "unexpected_body", rule = rule,
      })
    end
  end

  apply_decision({ action = "allow", rule = rule }, "allow_request")
end

return M
