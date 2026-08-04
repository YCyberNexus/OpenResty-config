-- V2 OpenResty 请求/响应处理：配置驱动的路径、Query、头、认证、正文和固定下一跳。
-- buffered 在完整响应校验通过前不向调用方发送正文；stream 仅用于显式批准的文件/SSE 路由。
local cjson = require("cjson.safe")
local factory = require("waf.factory")
local rules_lint = require("waf.rules_lint")
local RequestNormalizer = require("waf.request_normalizer")
local JsonValidator = require("waf.json_validator")
local RouteTable = require("waf.route_table")
local has_resty_sha256, resty_sha256 = pcall(require, "resty.sha256")
local has_resty_string, resty_string = pcall(require, "resty.string")

local M = {}
local decision
local route_table
local active_config = {}
local active_policies = {}
local limits = {}
local INTERNAL_BUFFERED_PREFIX = "/__waf_upstream/"
local INTERNAL_STREAM_PREFIX = "/__waf_stream/"

if type(cjson.decode_array_with_array_mt) == "function" then cjson.decode_array_with_array_mt(true) end
if type(cjson.decode_max_depth) == "function" then cjson.decode_max_depth(32) end
if type(cjson.decode_invalid_numbers) == "function" then cjson.decode_invalid_numbers(false) end
if type(cjson.encode_invalid_numbers) == "function" then cjson.encode_invalid_numbers(false) end

local function set_var(name, value)
  pcall(function() ngx.var[name] = tostring(value == nil and "-" or value) end)
end

local function to_hex(value)
  return (value:gsub(".", function(char) return string.format("%02x", string.byte(char)) end))
end

local function new_digest()
  if has_resty_sha256 then return resty_sha256:new() end
  return nil
end

local function digest_hex(digest)
  if not digest then return "unavailable" end
  local value = digest:final()
  if not value then return "unavailable" end
  if has_resty_string then return resty_string.to_hex(value) end
  return to_hex(value)
end

local function sha256(value)
  if type(value) ~= "string" then return "-" end
  local digest = new_digest()
  if digest and digest:update(value) then return digest_hex(digest) end
  if type(ngx.sha256_bin) ~= "function" then return "unavailable" end
  return to_hex(ngx.sha256_bin(value))
end

local function file_size(path)
  if type(path) ~= "string" or path == "" then return nil end
  local file = io.open(path, "rb")
  if not file then return nil end
  local size = file:seek("end")
  file:close()
  return size
end

local function read_body_file(path, max_bytes)
  local size = file_size(path)
  if not size then return nil, "read_failed" end
  if size > max_bytes then return nil, "too_large", size end
  local file = io.open(path, "rb")
  if not file then return nil, "read_failed" end
  local body = file:read("*a")
  file:close()
  return body, nil, size
end

local function sha256_file(path)
  local file = type(path) == "string" and io.open(path, "rb") or nil
  if not file then return "unavailable" end
  local digest = new_digest()
  if not digest then file:close() return "unavailable" end
  while true do
    local chunk = file:read(65536)
    if not chunk then break end
    if not digest:update(chunk) then file:close() return "unavailable" end
  end
  file:close()
  return digest_hex(digest)
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
  if not encoded then status, encoded = 500, '{"error":"response_encoding_failed"}' end
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
  return write_json(result.status or 400, {
    error = result.reason or "request_rejected",
    field = result.field,
    request_id = request_id(),
  })
end

local function deny_response(result)
  apply_decision(result, "deny_response")
  local body_policy = result.policy and result.policy.body
  if body_policy then set_var("waf_response_schema", body_policy.schema or body_policy.mode) end
  return write_json(result.status or 502, {
    error = result.reason or "upstream_response_rejected",
    field = result.field,
    request_id = request_id(),
  })
end

local function response_header(headers, wanted)
  local found
  for key, value in pairs(headers or {}) do
    if tostring(key):lower():gsub("_", "-") == wanted then
      if found ~= nil or type(value) == "table" then return nil, "duplicate" end
      found = tostring(value)
    end
  end
  return found
end

local function has_body_header(headers)
  local length = headers and headers["content-length"]
  if type(length) == "string" and length:match("^%d+$") and tonumber(length) > 0 then return true end
  local transfer = headers and headers["transfer-encoding"]
  return transfer ~= nil and transfer ~= ""
end

local function capture_method(method)
  return ngx["HTTP_" .. tostring(method or "")]
end

local function reset_request_state()
  local values = {
    waf_action = "unprocessed", waf_reason = "-", waf_field = "-", waf_rule_id = "-",
    waf_request_host = "-", waf_request_query = "", waf_forward_query = "",
    waf_forward_header_names = "-", waf_transport = "-", waf_timeout_profile = "-",
    waf_request_body = "", waf_request_body_bytes = 0, waf_request_body_sha256 = "-",
    waf_forward_body = "", waf_forward_body_bytes = 0, waf_forward_body_sha256 = "-",
    waf_upstream_origin = "-", waf_upstream_host = "-", waf_upstream_uri = "-",
    waf_upstream_addr = "-",
    waf_upstream_status = "-", waf_response_schema = "-", waf_response_body = "",
    waf_response_body_bytes = 0, waf_response_body_sha256 = "-",
    waf_forward_response_body = "", waf_forward_response_bytes = 0,
    waf_forward_response_sha256 = "-",
  }
  for name, value in pairs(values) do set_var(name, value) end
end

function M.init(config, routes, policies, node_role)
  config, routes, policies = config or {}, routes or {}, policies or {}
  local issues = rules_lint.lint(config, routes, policies)
  if rules_lint.count(issues, "error") > 0 then
    local first
    for _, issue in ipairs(issues) do if issue.level == "error" then first = issue break end end
    error("waf.handler: invalid V2 config at " .. tostring(first and first.where or "unknown")
      .. ": " .. tostring(first and first.msg or "validation failed"))
  end
  decision = factory.build_decision(config, {
    null_value = cjson.null,
    array_mt = cjson.array_mt,
  }, policies)
  route_table = RouteTable.new(routes, node_role)
  active_config, active_policies = config, policies
  limits = config.limits or {}
end

local function rule_accept_type(rule)
  local seen = {}
  for _, response in pairs(rule.responses or {}) do
    for _, media_type in ipairs(response.body and response.body.media_types or {}) do
      seen[media_type] = true
    end
  end
  local values = {}
  for value in pairs(seen) do values[#values + 1] = value end
  table.sort(values)
  return table.concat(values, ", ")
end

local function clear_request_headers(headers)
  if type(ngx.req.clear_header) ~= "function" then return end
  for name in pairs(headers or {}) do pcall(ngx.req.clear_header, name) end
end

local function set_request_header(name, value)
  if type(ngx.req.set_header) == "function" then ngx.req.set_header(name, value) end
end

local function sanitize_request(rule, raw_headers, forward_headers, content_type,
    normalized_body, body_file, body_present)
  clear_request_headers(raw_headers)
  local names = {}
  for name, value in pairs(forward_headers or {}) do
    set_request_header(name, value)
    names[#names + 1] = name
  end
  table.sort(names)
  set_var("waf_forward_header_names", #names > 0 and table.concat(names, ",") or "-")
  if content_type then set_request_header("content-type", content_type) end
  local accept = rule_accept_type(rule)
  if accept ~= "" then set_request_header("accept", accept) end
  if body_present then
    if normalized_body ~= nil and type(ngx.req.set_body_data) == "function" then
      ngx.req.set_body_data(normalized_body)
    elseif body_file and type(ngx.req.set_body_file) == "function" then
      ngx.req.set_body_file(body_file, true)
    end
  end
end

local function body_audit_enabled(rule)
  local body = rule.request and rule.request.body
  return body ~= nil and body.audit_body == true
end

function M.access()
  reset_request_state()
  ngx.ctx = ngx.ctx or {}

  local host, method, path = ngx.var.host, ngx.req.get_method(), ngx.var.uri
  local request_uri = ngx.var.request_uri
  local raw_path = type(request_uri) == "string" and request_uri:match("^([^?]*)") or nil
  local raw_headers, headers_err = ngx.req.get_headers()
  local preliminary_headers, normalized_err = RequestNormalizer.normalize_headers(raw_headers)
  if not preliminary_headers then
    return deny_request({ action = "deny", status = normalized_err.status,
      reason = normalized_err.reason, field = normalized_err.field })
  end
  local query_present = ngx.var.is_args == "?"
    or (type(request_uri) == "string" and request_uri:find("?", 1, true) ~= nil)
  local precheck = decision:match({
    host = host, method = method, path = path, raw_path = raw_path,
    args = ngx.var.args, query_present = query_present,
    headers = raw_headers, headers_truncated = headers_err == "truncated",
    body_present = has_body_header(preliminary_headers),
  })
  if precheck.action == "deny" then return deny_request(precheck) end
  local rule = precheck.rule
  local route = route_table and route_table:resolve(host)
  if not route then
    return deny_request({ action = "deny", status = 500, reason = "route_missing", rule = rule })
  end
  local timeout_profile = rule.timeout_profile or route.timeout_profile
  if not (active_policies.timeout_profiles and active_policies.timeout_profiles[timeout_profile]) then
    return deny_request({ action = "deny", status = 500,
      reason = "timeout_profile_missing", rule = rule })
  end

  set_var("waf_rule_id", rule.id)
  set_var("waf_request_host", host)
  set_var("waf_request_query", ngx.var.args or "")
  set_var("waf_transport", rule.transport)
  set_var("waf_timeout_profile", timeout_profile)
  set_var("waf_upstream_origin", route.origin)
  set_var("waf_upstream_host", route.upstream_host)

  local request_policy = rule.request or {}
  local query, forward_query = {}, ""
  if request_policy.query_schema then
    query, forward_query = RequestNormalizer.parse_query(
      ngx.var.args or "", active_config.schemas[request_policy.query_schema],
      limits.max_query_string_bytes, 64)
    if not query then
      forward_query.rule = rule
      forward_query.action = "deny"
      return deny_request(forward_query)
    end
  end
  set_var("waf_forward_query", forward_query)
  set_var("waf_upstream_uri", path .. (forward_query ~= "" and ("?" .. forward_query) or ""))

  ngx.req.read_body()
  local raw_body, body_file = ngx.req.get_body_data(), ngx.req.get_body_file()
  local size = raw_body and #raw_body or (body_file and file_size(body_file) or 0)
  if size == nil then
    return deny_request({ action = "deny", status = 400, reason = "request_body_read_failed", rule = rule })
  end
  local body_present = size > 0
  local body_policy = request_policy.body
  if body_present and not body_policy then
    return deny_request({ action = "deny", status = 400, reason = "unexpected_body", rule = rule })
  end
  if body_policy and size > body_policy.max_body_bytes then
    return deny_request({ action = "deny", status = 413, reason = "request_body_too_large", rule = rule })
  end

  local original_sha = "-"
  if body_present then
    if raw_body then
      original_sha = sha256(raw_body)
    elseif rule.transport == "buffered" or size <= limits.max_buffered_request_body_bytes then
      original_sha = sha256_file(body_file)
    else
      -- 避免在 OpenResty event loop 中同步读取最多 64 MiB 的临时文件造成 worker 阻塞。
      original_sha = "not_computed_stream_file"
    end
  end
  set_var("waf_request_body_bytes", size)
  set_var("waf_request_body_sha256", original_sha)
  if body_present and body_audit_enabled(rule) then
    if raw_body == nil then
      raw_body = select(1, read_body_file(body_file, body_policy.max_body_bytes))
      if raw_body == nil then
        return deny_request({ action = "deny", status = 400,
          reason = "request_body_read_failed", rule = rule })
      end
    end
    set_var("waf_request_body", raw_body)
  end

  local body_value, normalized_body, forward_content_type
  if body_present then
    local allowed, base_type = RequestNormalizer.media_type_allowed(
      preliminary_headers["content-type"] or ngx.var.content_type, body_policy.media_types)
    if not allowed then
      return deny_request({ action = "deny", status = 415,
        reason = "unsupported_media_type", field = "content-type", rule = rule })
    end
    if body_policy.mode == "json" or body_policy.mode == "text"
      or rule.transport == "buffered" then
      if raw_body == nil then
        raw_body = select(1, read_body_file(body_file, body_policy.max_body_bytes))
        if raw_body == nil then
          return deny_request({ action = "deny", status = 400,
            reason = "request_body_read_failed", rule = rule })
        end
      end
    end
    if body_policy.mode == "json" then
      body_value = cjson.decode(raw_body)
      if body_value == nil then
        return deny_request({ action = "deny", status = 400, reason = "invalid_json", rule = rule })
      end
      normalized_body = cjson.encode(body_value)
      if normalized_body == nil then
        return deny_request({ action = "deny", status = 500,
          reason = "request_normalization_failed", rule = rule })
      end
      forward_content_type = "application/json"
    elseif body_policy.mode == "text" then
      body_value, normalized_body = raw_body, raw_body
      forward_content_type = preliminary_headers["content-type"] or base_type
    else
      normalized_body = raw_body -- stream 文件仍为 nil，由原始临时文件转发。
      forward_content_type = preliminary_headers["content-type"] or base_type
    end
  end

  local validated = decision:validate_request(rule, {
    body = body_value, body_present = body_present, query = query,
    headers = precheck.headers,
  })
  if validated.action == "deny" then return deny_request(validated) end
  if normalized_body and #normalized_body > body_policy.max_body_bytes then
    return deny_request({ action = "deny", status = 413,
      reason = "request_body_too_large", rule = rule })
  end

  sanitize_request(rule, raw_headers, validated.forward_headers, forward_content_type,
    normalized_body, body_file, body_present)
  local forward_size = normalized_body and #normalized_body or size
  local forward_sha = body_present and (normalized_body and sha256(normalized_body) or original_sha) or "-"
  set_var("waf_forward_body_bytes", forward_size)
  set_var("waf_forward_body_sha256", forward_sha)
  if body_present and body_audit_enabled(rule) and normalized_body then
    set_var("waf_forward_body", normalized_body)
  end

  ngx.ctx.waf_rule = rule
  ngx.ctx.waf_method = method
  ngx.ctx.waf_path = path
  ngx.ctx.waf_forward_args = forward_query
  ngx.ctx.waf_forward_body = normalized_body
  ngx.ctx.waf_body_file = body_file
  ngx.ctx.waf_body_present = body_present
  ngx.ctx.waf_transport = rule.transport
  ngx.ctx.waf_timeout_profile = timeout_profile
  apply_decision({ action = "allow", rule = rule }, "allow_request")
end

local function validate_forward_headers(definitions, headers)
  local output = {}
  for name, definition in pairs(definitions or {}) do
    local value, err = response_header(headers, name)
    if err then return nil, { reason = "duplicate_upstream_header", field = name } end
    if value == nil then
      if definition.required then return nil, { reason = "required_upstream_header_missing", field = name } end
    else
      local ok, validation = JsonValidator.new(definition.schema):validate(value)
      if not ok then return nil, { reason = "upstream_header", field = name .. ":" .. validation.field } end
      output[name] = value
    end
  end
  return output
end

local function validate_content_headers(body_policy, headers)
  local encoding, encoding_err = response_header(headers, "content-encoding")
  if encoding_err then return nil, { reason = "duplicate_upstream_header", field = "content-encoding" } end
  if encoding and encoding ~= "" and encoding:lower() ~= "identity" then
    return nil, { reason = "response_content_encoding_not_allowed", field = "content-encoding" }
  end
  if body_policy.mode == "empty" then return { content_type = nil } end
  local content_type, content_type_err = response_header(headers, "content-type")
  if content_type_err then return nil, { reason = "duplicate_upstream_header", field = "content-type" } end
  local allowed = RequestNormalizer.media_type_allowed(content_type, body_policy.media_types)
  if not allowed then
    return nil, { reason = "response_unsupported_media_type", field = "content-type" }
  end
  return { content_type = content_type }
end

local function apply_output_headers(headers)
  for name, value in pairs(headers or {}) do ngx.header[name] = value end
end

local function buffered_proxy(ctx, rule)
  if not ngx.location or type(ngx.location.capture) ~= "function" then
    return deny_response({ status = 500, reason = "response_capture_unavailable", rule = rule })
  end
  local method = capture_method(ctx.waf_method)
  if method == nil then return deny_response({ status = 500, reason = "unsupported_proxy_method", rule = rule }) end
  -- 只把内部代理所需变量复制给子请求；不使用 copy_all_vars/share_all_vars。
  local opts = {
    method = method,
    ctx = ctx,
    vars = {
      waf_upstream_origin = ngx.var.waf_upstream_origin,
      waf_upstream_host = ngx.var.waf_upstream_host,
      waf_upstream_uri = ngx.var.waf_upstream_uri,
      waf_trace_id = ngx.var.waf_trace_id,
    },
  }
  if ctx.waf_forward_body ~= nil then opts.body = ctx.waf_forward_body end
  local uri = INTERNAL_BUFFERED_PREFIX .. ctx.waf_timeout_profile .. ctx.waf_path
  local ok, response = pcall(ngx.location.capture, uri, opts)
  if not ok or type(response) ~= "table" or type(response.status) ~= "number" then
    return deny_response({ status = 502, reason = "upstream_capture_failed", rule = rule })
  end

  local upstream_addr = response_header(response.header, "x-waf-internal-upstream-addr")
  set_var("waf_upstream_addr", upstream_addr or "-")
  set_var("waf_upstream_status", response.status)
  local raw = type(response.body) == "string" and response.body or ""
  set_var("waf_response_body_bytes", #raw)
  set_var("waf_response_body_sha256", sha256(raw))
  if response.truncated then
    return deny_response({ status = 502, reason = "response_body_too_large", rule = rule })
  end
  local policy, rejected = decision:response_policy(rule, response.status)
  if not policy then return deny_response(rejected) end
  local body_policy = policy.body
  if body_policy.audit_body == true then set_var("waf_response_body", raw) end
  set_var("waf_response_schema", body_policy.schema or body_policy.mode)
  if #raw > limits.max_buffered_response_body_bytes or
    (body_policy.max_body_bytes and #raw > body_policy.max_body_bytes) then
    return deny_response({ status = 502, reason = "response_body_too_large",
      rule = rule, policy = policy })
  end
  if body_policy.mode == "empty" and #raw ~= 0 then
    return deny_response({ status = 502, reason = "unexpected_response_body", rule = rule, policy = policy })
  end
  local content, content_err = validate_content_headers(body_policy, response.header)
  if not content then content_err.status, content_err.rule, content_err.policy = 502, rule, policy
    return deny_response(content_err) end
  local output_headers, header_err = validate_forward_headers(policy.headers, response.header)
  if not output_headers then header_err.status, header_err.rule, header_err.policy = 502, rule, policy
    return deny_response(header_err) end

  local normalized = raw
  if body_policy.mode == "json" then
    local value = cjson.decode(raw)
    if value == nil then return deny_response({ status = 502, reason = "invalid_upstream_json",
      rule = rule, policy = policy }) end
    local validated = decision:validate_response(rule, response.status, value)
    if validated.action == "deny" then return deny_response(validated) end
    normalized = cjson.encode(value)
    if normalized == nil then return deny_response({ status = 502,
      reason = "response_normalization_failed", rule = rule, policy = policy }) end
  elseif body_policy.mode == "text" then
    local validated = decision:validate_response(rule, response.status, raw)
    if validated.action == "deny" then return deny_response(validated) end
  end
  if body_policy.max_body_bytes and #normalized > body_policy.max_body_bytes then
    return deny_response({ status = 502, reason = "response_body_too_large", rule = rule, policy = policy })
  end
  if body_policy.audit_body == true then set_var("waf_forward_response_body", normalized) end
  set_var("waf_forward_response_bytes", #normalized)
  set_var("waf_forward_response_sha256", sha256(normalized))
  apply_decision({ action = "allow", rule = rule }, "allow_response")
  ngx.status = response.status
  if content.content_type then ngx.header.content_type = body_policy.mode == "json"
    and "application/json" or content.content_type end
  ngx.header.content_length = #normalized
  apply_output_headers(output_headers)
  if normalized ~= "" then ngx.print(normalized) end
  return ngx.exit(response.status)
end

function M.proxy()
  local ctx, rule = ngx.ctx or {}, (ngx.ctx or {}).waf_rule
  if not rule then return deny_response({ status = 500, reason = "request_context_missing" }) end
  if type(ctx.waf_path) ~= "string" or ctx.waf_path:sub(1, 1) ~= "/" then
    return deny_response({ status = 500, reason = "request_context_missing", rule = rule })
  end
  if ctx.waf_transport == "stream" then
    if type(ngx.exec) ~= "function" then
      return deny_response({ status = 500, reason = "stream_proxy_unavailable", rule = rule })
    end
    local uri = INTERNAL_STREAM_PREFIX .. ctx.waf_timeout_profile .. ctx.waf_path
    return ngx.exec(uri)
  end
  return buffered_proxy(ctx, rule)
end

local function clear_stream_headers()
  local names = {}
  for name in pairs(ngx.header or {}) do names[#names + 1] = name end
  for _, name in ipairs(names) do ngx.header[name] = nil end
end

local function stream_reject(reason, field, policy)
  local ctx, rule = ngx.ctx or {}, (ngx.ctx or {}).waf_rule
  local encoded = cjson.encode({ error = reason, field = field, request_id = request_id() })
    or '{"error":"upstream_response_rejected"}'
  ctx.waf_stream_denied = true
  ctx.waf_stream_error_body = encoded
  ctx.waf_stream_policy = policy
  apply_decision({ action = "deny", reason = reason, field = field, rule = rule }, "deny_response")
  clear_stream_headers()
  ngx.status = 502
  ngx.header.content_type = "application/json"
  ngx.header.content_length = #encoded
  set_var("waf_forward_response_body", encoded)
  set_var("waf_forward_response_bytes", #encoded)
  set_var("waf_forward_response_sha256", sha256(encoded))
end

function M.upstream_header_filter()
  local ctx, rule = ngx.ctx or {}, (ngx.ctx or {}).waf_rule
  if not rule then return end
  set_var("waf_upstream_addr", ngx.var.upstream_addr or "-")
  set_var("waf_upstream_status", ngx.status or "-")
  if ctx.waf_transport ~= "stream" then
    ngx.header["X-WAF-Internal-Upstream-Addr"] = ngx.var.upstream_addr or "-"
    return
  end
  local policy, rejected = decision:response_policy(rule, ngx.status)
  if not policy then return stream_reject(rejected.reason, rejected.field) end
  local body_policy = policy.body
  set_var("waf_response_schema", body_policy.schema or body_policy.mode)
  local content, content_err = validate_content_headers(body_policy, ngx.header)
  if not content then return stream_reject(content_err.reason, content_err.field, policy) end
  local output_headers, header_err = validate_forward_headers(policy.headers, ngx.header)
  if not output_headers then return stream_reject(header_err.reason, header_err.field, policy) end
  local length = response_header(ngx.header, "content-length")
  if length and (not length:match("^%d+$") or tonumber(length) > body_policy.max_body_bytes) then
    return stream_reject("response_body_too_large", "content-length", policy)
  end
  clear_stream_headers()
  if content.content_type then ngx.header.content_type = content.content_type end
  if length then ngx.header.content_length = tonumber(length) end
  apply_output_headers(output_headers)
  ctx.waf_stream_policy = policy
  ctx.waf_stream_body_policy = body_policy
  ctx.waf_stream_digest = new_digest()
  ctx.waf_stream_bytes = 0
  apply_decision({ action = "allow", rule = rule }, "allow_response")
end

function M.stream_body_filter()
  local ctx = ngx.ctx or {}
  if ctx.waf_transport ~= "stream" then return end
  if ctx.waf_stream_denied then
    if not ctx.waf_stream_error_sent then
      ngx.arg[1], ngx.arg[2] = ctx.waf_stream_error_body, true
      ctx.waf_stream_error_sent = true
    else
      ngx.arg[1], ngx.arg[2] = nil, true
    end
    return
  end
  local chunk = type(ngx.arg[1]) == "string" and ngx.arg[1] or ""
  local body_policy = ctx.waf_stream_body_policy
  if not body_policy then ngx.arg[1], ngx.arg[2] = nil, true return end
  local next_size = (ctx.waf_stream_bytes or 0) + #chunk
  if body_policy.mode == "empty" and #chunk > 0 then
    apply_decision({ action = "deny", reason = "unexpected_response_body",
      rule = ctx.waf_rule }, "deny_response")
    ngx.arg[1], ngx.arg[2] = nil, true
    return
  end
  if body_policy.max_body_bytes and next_size > body_policy.max_body_bytes then
    apply_decision({ action = "deny", reason = "response_body_too_large",
      rule = ctx.waf_rule }, "deny_response")
    set_var("waf_response_body_bytes", next_size)
    ngx.arg[1], ngx.arg[2] = nil, true
    return
  end
  ctx.waf_stream_bytes = next_size
  if ctx.waf_stream_digest and #chunk > 0 then ctx.waf_stream_digest:update(chunk) end
  if ngx.arg[2] then
    local digest = digest_hex(ctx.waf_stream_digest)
    set_var("waf_response_body_bytes", next_size)
    set_var("waf_response_body_sha256", digest)
    set_var("waf_forward_response_bytes", next_size)
    set_var("waf_forward_response_sha256", digest)
  end
end

return M
