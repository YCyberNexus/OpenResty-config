-- OpenResty IO 胶水：请求预检/解析、双向 schema 校验、受控子请求代理、审计变量。
-- 规则判断在 decision/json_validator 中；本模块不记录原始请求或响应正文。
local cjson = require("cjson.safe")
local factory = require("waf.factory")
local regex = require("waf.regex")
local rules_lint = require("waf.rules_lint")

local M = {}
local decision
local max_request_body_bytes = 16384
local max_response_body_bytes = 4194304
local policy_version = "unknown"
local policy_direction = "unknown"

-- OpenResty 的 lua-cjson 支持给解码后的数组加 metatable。开启后才能严格区分
-- 空数组 [] 与空对象 {}，避免 schema 类型绕过；测试替身也实现同一接口。
if type(cjson.decode_array_with_array_mt) == "function" then
  cjson.decode_array_with_array_mt(true)
end
if type(cjson.decode_max_depth) == "function" then cjson.decode_max_depth(32) end
if type(cjson.decode_invalid_numbers) == "function" then cjson.decode_invalid_numbers(false) end
if type(cjson.encode_invalid_numbers) == "function" then cjson.encode_invalid_numbers(false) end

local function set_var(name, value)
  -- 生产 nginx 配置会先用 set 声明变量；pcall 仅用于让纯 Lua mock 测试保持轻量。
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
  set_var("waf_response_body_bytes", #encoded)
  set_var("waf_response_body_sha256", sha256(encoded))
  ngx.print(encoded)
  return ngx.exit(status)
end

local function deny_request(result, method, path)
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

local METHOD_CONSTANTS = {
  GET = function() return ngx.HTTP_GET end,
  POST = function() return ngx.HTTP_POST end,
  PUT = function() return ngx.HTTP_PUT end,
  PATCH = function() return ngx.HTTP_PATCH end,
  DELETE = function() return ngx.HTTP_DELETE end,
}

function M.init(config, opts)
  config = config or {}
  opts = opts or {}
  local issues = rules_lint.lint(config, { production = opts.production == true })
  if rules_lint.count(issues, "error") > 0 then
    local first
    for _, issue in ipairs(issues) do
      if issue.level == "error" then first = issue break end
    end
    error("waf.handler: invalid operations rules at " .. tostring(first and first.where or "unknown")
      .. ": " .. tostring(first and first.msg or "validation failed"))
  end
  if type(opts.allowed_hosts) ~= "table" or #opts.allowed_hosts == 0 then
    error("waf.handler: allowed_hosts must be explicitly configured for this node")
  end
  decision = factory.build_decision(config, regex.match, {
    null_value = cjson.null,
    array_mt = cjson.array_mt,
    allowed_hosts = opts.allowed_hosts,
  })
  max_request_body_bytes = config.max_request_body_bytes or max_request_body_bytes
  max_response_body_bytes = config.max_response_body_bytes or max_response_body_bytes
  policy_version = config.version or "unknown"
  policy_direction = config.direction or "unknown"
end

function M.access()
  set_var("waf_action", "unprocessed")
  set_var("waf_policy_version", policy_version)
  set_var("waf_policy_direction", policy_direction)
  set_var("waf_reason", "-")
  set_var("waf_field", "-")
  set_var("waf_rule_id", "-")
  set_var("waf_request_body_bytes", 0)
  set_var("waf_request_body_sha256", "-")
  set_var("waf_forward_body_bytes", 0)
  set_var("waf_forward_body_sha256", "-")
  set_var("waf_upstream_content_type", "")
  set_var("waf_upstream_body_bytes", 0)
  set_var("waf_upstream_body_sha256", "-")
  set_var("waf_response_body_bytes", 0)
  set_var("waf_response_body_sha256", "-")
  set_var("waf_upstream_status", "-")

  local method = ngx.req.get_method()
  local path = ngx.var.uri
  local request_uri = ngx.var.request_uri
  local headers, headers_err = ngx.req.get_headers()
  local precheck = decision:match({
    method = method,
    path = path,
    -- $host 在缺 Host 头时会回退到 server_name；跨区白名单必须要求客户端显式提供 Host。
    host = headers and headers["host"] and ngx.var.host or nil,
    args = ngx.var.args,
    -- $is_args 对空 query 的行为依赖 Nginx 是否认为参数长度为零；同时检查原始
    -- request-target，确保尾随的裸 `?` 也不会绕过“禁止 query”策略。
    query_present = ngx.var.is_args == "?"
      or (type(request_uri) == "string" and request_uri:find("?", 1, true) ~= nil),
    headers = headers,
    headers_truncated = headers_err == "truncated",
    body_present = has_body_header(headers),
  })
  if precheck.action == "deny" then return deny_request(precheck, method, path) end

  local rule = precheck.rule
  set_var("waf_rule_id", rule.id)
  local body
  if rule.request_schema then
    if not is_json_media_type(ngx.var.content_type) then
      return deny_request({
        action = "deny", status = 415, reason = "unsupported_media_type", rule = rule,
      }, method, path)
    end
    -- 不把客户端提供的大小写、参数或重复语义带给下游；校验通过后重建成唯一媒体类型。
    set_var("waf_upstream_content_type", "application/json")

    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if raw == nil and ngx.req.get_body_file() ~= nil then
      return deny_request({
        action = "deny", status = 413, reason = "request_body_too_large", rule = rule,
      }, method, path)
    end
    if raw ~= nil then
      set_var("waf_request_body_bytes", #raw)
      set_var("waf_request_body_sha256", sha256(raw))
      if #raw > max_request_body_bytes then
        return deny_request({
          action = "deny", status = 413, reason = "request_body_too_large", rule = rule,
        }, method, path)
      end
      local decoded = cjson.decode(raw)
      if decoded == nil then
        return deny_request({
          action = "deny", status = 400, reason = "invalid_json", rule = rule,
        }, method, path)
      end
      body = decoded
    end

    local validated = decision:validate_request(rule, body)
    if validated.action == "deny" then return deny_request(validated, method, path) end

    -- 转发重新编码后的等价 JSON，而不是客户端原始字节。这样重复 object key 等解析
    -- 歧义只能按 WAF 已校验的单一语义到达下一跳，避免不同 JSON 解析器产生策略绕过。
    local normalized = cjson.encode(body)
    if normalized == nil then
      return deny_request({
        action = "deny", status = 500, reason = "request_normalization_failed", rule = rule,
      }, method, path)
    end
    if #normalized > max_request_body_bytes then
      return deny_request({
        action = "deny", status = 413, reason = "request_body_too_large", rule = rule,
      }, method, path)
    end
    ngx.req.set_body_data(normalized)
    set_var("waf_forward_body_bytes", #normalized)
    set_var("waf_forward_body_sha256", sha256(normalized))
  else
    -- HTTP/2 可以携带没有 Content-Length/Transfer-Encoding 的 DATA 帧。仅看请求头会
    -- 漏掉这种 GET 正文，因此对白名单中的无正文接口实际读取一次后再 fail-closed。
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
      }, method, path)
    end
  end

  ngx.ctx.waf_rule = rule
  ngx.ctx.waf_request_body = body
  apply_decision({ action = "allow", rule = rule }, "allow_request")
end

local function response_header(headers, wanted)
  wanted = wanted:lower()
  for key, value in pairs(headers or {}) do
    if tostring(key):lower() == wanted then
      if type(value) == "table" then
        if #value ~= 1 then return nil, "multiple" end
        return value[1]
      end
      return value, nil
    end
  end
end

local function deny_upstream(result, method, path)
  apply_decision(result, "deny_response")
  -- 对调用方只返回契约内的通用错误，不回显上游正文、字段或内部规则。
  return write_json(502, { detail = "Upstream response rejected" })
end

function M.proxy()
  local method = ngx.req.get_method()
  local path = ngx.var.uri
  local rule = ngx.ctx.waf_rule
  if not rule then
    return deny_upstream({ action = "deny", status = 502, reason = "missing_request_context" }, method, path)
  end

  local method_factory = METHOD_CONSTANTS[method]
  if not method_factory or method_factory() == nil then
    return deny_upstream({
      action = "deny", status = 502, reason = "unsupported_proxy_method", rule = rule,
    }, method, path)
  end

  local response = ngx.location.capture("/_waf_upstream" .. path, {
    method = method_factory(),
    args = ngx.var.args,
    always_forward_body = rule.request_schema ~= nil,
    -- 子请求必须拿到 access 阶段写入的正文长度、trace 与审计变量；复制后相互隔离。
    copy_all_vars = true,
  })
  if type(response) ~= "table" then
    set_var("waf_upstream_status", "capture_failed")
    return deny_upstream({
      action = "deny", status = 502, reason = "upstream_unavailable", rule = rule,
    }, method, path)
  end

  set_var("waf_upstream_status", response.status or "-")
  local raw = response.body or ""
  set_var("waf_upstream_body_bytes", #raw)
  set_var("waf_upstream_body_sha256", sha256(raw))

  if response.truncated or #raw > max_response_body_bytes then
    return deny_upstream({
      action = "deny", status = 502, reason = "response_body_too_large", rule = rule,
    }, method, path)
  end
  local response_content_type, response_content_type_err = response_header(response.header, "content-type")
  if response_content_type_err or not is_json_media_type(response_content_type) then
    return deny_upstream({
      action = "deny", status = 502, reason = "response_media_type", rule = rule,
    }, method, path)
  end

  local decoded = cjson.decode(raw)
  if decoded == nil then
    return deny_upstream({
      action = "deny", status = 502, reason = "response_invalid_json", rule = rule,
    }, method, path)
  end
  local validated = decision:validate_response(rule, response.status, decoded, ngx.ctx.waf_request_body)
  if validated.action == "deny" then return deny_upstream(validated, method, path) end

  -- 与请求侧相同，调用方只接收已经按 schema 校验过的单一 JSON 语义，不能收到
  -- 包含重复 object key 的原始上游字节。
  local normalized = cjson.encode(decoded)
  if normalized == nil or #normalized > max_response_body_bytes then
    return deny_upstream({
      action = "deny", status = 502, reason = "response_normalization_failed", rule = rule,
    }, method, path)
  end

  apply_decision({ action = "allow", rule = rule }, "allow_response")
  set_var("waf_response_body_bytes", #normalized)
  set_var("waf_response_body_sha256", sha256(normalized))
  ngx.status = response.status
  ngx.header.content_type = "application/json"
  local retry_after = response_header(response.header, "retry-after")
  if response.status == 503 and type(retry_after) == "string" and retry_after:match("^%d+$") then
    ngx.header["Retry-After"] = retry_after
  end
  ngx.print(normalized)
end

return M
