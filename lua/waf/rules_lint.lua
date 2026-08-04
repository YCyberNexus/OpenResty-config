-- V2 静态体检：接口契约、固定路由、认证/业务策略和技术硬上限统一 fail-closed 校验。
local JsonValidator = require("waf.json_validator")
local UrlFilter = require("waf.url_filter")

local M = {}

local HARD_LIMITS = {
  max_query_string_bytes = 32768,
  max_buffered_request_body_bytes = 1048576,
  max_buffered_response_body_bytes = 1048576,
  max_stream_request_body_bytes = 67108864,
  max_stream_response_body_bytes = 268435456,
}
local KNOWN_METHODS = {
  GET = true, HEAD = true, POST = true, PUT = true, PATCH = true,
  DELETE = true, OPTIONS = true,
}
local KNOWN_TYPES = {
  object = true, array = true, string = true, integer = true,
  number = true, boolean = true, ["null"] = true,
}
local KNOWN_SCHEMA_KEYS = {
  type = true, required = true, properties = true, additional_properties = true,
  max_properties = true, items = true, min_items = true, max_items = true,
  min_length = true, max_length = true, max_bytes = true, non_blank = true,
  trimmed = true, prefix = true, format = true, minimum = true, maximum = true,
  enum = true, contract = true,
}
local KNOWN_CONFIG_KEYS = { version = true, limits = true, whitelist = true, schemas = true }
local KNOWN_LIMIT_KEYS = {}
for key in pairs(HARD_LIMITS) do KNOWN_LIMIT_KEYS[key] = true end
local KNOWN_RULE_KEYS = {
  id = true, host = true, methods = true, path = true, path_template = true,
  path_parameters = true, transport = true, timeout_profile = true,
  auth_policy = true, request = true, responses = true,
  -- 仅用于给 V1 配置明确迁移错误，不能被静默忽略。
  request_schema = true, pattern = true, allow_query = true, body = true,
}
local KNOWN_REQUEST_KEYS = { query_schema = true, headers = true, body = true, policies = true }
local KNOWN_BODY_KEYS = {
  mode = true, required = true, media_types = true, schema = true,
  max_body_bytes = true, audit_body = true,
}
local KNOWN_RESPONSE_KEYS = { body = true, headers = true }
local KNOWN_HEADER_KEYS = { required = true, schema = true }
local KNOWN_ROUTE_CONFIG_KEYS = { version = true, required_node_roles = true, nodes = true }
local KNOWN_ROUTE_KEYS = {
  scheme = true, address = true, port = true, upstream_host = true, timeout_profile = true,
}
local KNOWN_POLICY_CONFIG_KEYS = {
  version = true, timeout_profiles = true, auth = true, request_policies = true,
}
local KNOWN_AUTH_KEYS = { mode = true, header = true, max_bytes = true }
local KNOWN_REQUEST_POLICY_KEYS = { kind = true, field = true }
local PREDEFINED_TIMEOUTS = { fast = true, standard = true, long = true }
local RESERVED_REQUEST_HEADERS = {
  host = true, ["content-length"] = true, ["content-type"] = true,
  connection = true, ["transfer-encoding"] = true, ["accept-encoding"] = true,
  ["x-waf-trace-id"] = true, ["x-waf-internal-upstream-addr"] = true,
  authorization = true, ["x-api-key"] = true,
}
local FORBIDDEN_RESPONSE_HEADERS = {
  connection = true, ["transfer-encoding"] = true, ["content-length"] = true,
  ["content-type"] = true, ["content-encoding"] = true,
  ["x-waf-internal-upstream-addr"] = true,
}

local function reserved_internal_path(value)
  return type(value) == "string" and (value == "/__waf_upstream"
    or value:sub(1, 16) == "/__waf_upstream/"
    or value == "/__waf_stream" or value:sub(1, 14) == "/__waf_stream/")
end

local function is_array(value)
  if type(value) ~= "table" then return false end
  local count, highest = 0, 0
  for key in pairs(value) do
    if type(key) ~= "number" or key < 1 or key ~= math.floor(key) then return false end
    count = count + 1
    if key > highest then highest = key end
  end
  return count == highest
end

local function nonempty_array(value)
  return is_array(value) and next(value) ~= nil
end

local function positive_integer(value)
  return type(value) == "number" and value > 0 and value == math.floor(value)
end

local function valid_header_name(value)
  return type(value) == "string" and value == value:lower()
    and value:match("^[a-z0-9!#$%%&'*+.^_`|~-]+$") ~= nil
end

local function valid_host(value)
  if type(value) ~= "string" or value == "" or #value > 253 or value ~= value:lower()
    or value:find(":", 1, true) or value:find("/", 1, true)
    or value:find("%s") or value:find("%.%.")
    or value:sub(1, 1) == "." or value:sub(-1) == "." then return false end
  for label in value:gmatch("[^.]+") do
    if #label > 63 or not label:match("^[a-z0-9][a-z0-9-]*[a-z0-9]$") then
      if not label:match("^[a-z0-9]$") then return false end
    end
  end
  return true
end

local function valid_ipv4(value)
  if type(value) ~= "string" then return false end
  local count = 0
  for part in value:gmatch("[^.]+") do
    count = count + 1
    if not part:match("^%d+$") or (#part > 1 and part:sub(1, 1) == "0")
      or tonumber(part) > 255 then return false end
  end
  return count == 4 and value:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
end

local function type_has(schema, wanted)
  if type(schema) ~= "table" then return false end
  if schema.type == wanted then return true end
  for _, value in ipairs(type(schema.type) == "table" and schema.type or {}) do
    if value == wanted then return true end
  end
  return false
end

local function check_known_keys(value, known, at, add)
  for key in pairs(type(value) == "table" and value or {}) do
    if type(key) ~= "string" or not known[key] then
      add("error", at .. "." .. tostring(key), "未知配置关键字；可能是拼写错误")
    end
  end
end

local function check_schema(schema, at, add)
  if type(schema) ~= "table" then add("error", at, "schema 必须是 table") return end
  check_known_keys(schema, KNOWN_SCHEMA_KEYS, at, add)
  local declared = schema.type
  if type(declared) == "string" then
    if not KNOWN_TYPES[declared] then add("error", at .. ".type", "未知 JSON 类型：" .. declared) end
  elseif not nonempty_array(declared) then
    add("error", at .. ".type", "type 必须是类型名或非空类型数组")
  else
    local seen = {}
    for _, item in ipairs(declared) do
      if type(item) ~= "string" or not KNOWN_TYPES[item] then
        add("error", at .. ".type", "类型数组包含未知 JSON 类型")
      elseif seen[item] then
        add("warn", at .. ".type", "类型数组包含重复项：" .. item)
      else
        seen[item] = true
      end
    end
  end

  if type_has(schema, "object") then
    if type(schema.properties) ~= "table" then
      add("error", at .. ".properties", "object 必须显式配置 properties")
    end
    if schema.additional_properties ~= false and schema.additional_properties ~= true then
      add("error", at .. ".additional_properties",
        "object 必须显式配置 additional_properties=false 或 true")
    elseif schema.additional_properties == true then
      add("warn", at .. ".additional_properties",
        "该 object 显式放行任意未登记字段；必须记录业务确认与安全偏离")
    end
    if schema.max_properties ~= nil and (type(schema.max_properties) ~= "number"
      or schema.max_properties < 0 or schema.max_properties ~= math.floor(schema.max_properties)) then
      add("error", at .. ".max_properties", "max_properties 必须是非负整数")
    end
    local properties = type(schema.properties) == "table" and schema.properties or {}
    if schema.required ~= nil and not is_array(schema.required) then
      add("error", at .. ".required", "required 必须是数组")
    else
      local seen = {}
      for _, key in ipairs(schema.required or {}) do
        if type(key) ~= "string" or properties[key] == nil then
          add("error", at .. ".required", "required 引用了未定义字段：" .. tostring(key))
        elseif seen[key] then
          add("warn", at .. ".required", "required 包含重复字段：" .. key)
        end
        seen[key] = true
      end
    end
    for key, child in pairs(properties) do
      if type(key) ~= "string" or key == "" then
        add("error", at .. ".properties", "属性名必须是非空字符串")
      else
        check_schema(child, at .. ".properties." .. key, add)
      end
    end
  end

  local applicability = {
    required = type_has(schema, "object"), properties = type_has(schema, "object"),
    additional_properties = type_has(schema, "object"), max_properties = type_has(schema, "object"),
    items = type_has(schema, "array"), min_items = type_has(schema, "array"),
    max_items = type_has(schema, "array"), min_length = type_has(schema, "string"),
    max_length = type_has(schema, "string"), max_bytes = type_has(schema, "string"),
    non_blank = type_has(schema, "string"), trimmed = type_has(schema, "string"),
    prefix = type_has(schema, "string"), format = type_has(schema, "string"),
    minimum = type_has(schema, "number") or type_has(schema, "integer"),
    maximum = type_has(schema, "number") or type_has(schema, "integer"),
  }
  for key, applies in pairs(applicability) do
    if schema[key] ~= nil and not applies then
      add("error", at .. "." .. key, key .. " 与声明类型不匹配，运行时不会应用")
    end
  end

  if type_has(schema, "array") then
    if type(schema.items) ~= "table" then
      add("error", at .. ".items", "array 必须配置 items schema")
    else
      check_schema(schema.items, at .. ".items", add)
    end
    for _, key in ipairs({ "min_items", "max_items" }) do
      local value = schema[key]
      if value ~= nil and (type(value) ~= "number" or value < 0
        or value ~= math.floor(value)) then add("error", at .. "." .. key, key .. " 必须是非负整数") end
    end
    if type(schema.min_items) == "number" and type(schema.max_items) == "number"
      and schema.min_items > schema.max_items then add("error", at, "min_items 不能大于 max_items") end
  end

  if type_has(schema, "string") then
    for _, key in ipairs({ "min_length", "max_length", "max_bytes" }) do
      local value = schema[key]
      if value ~= nil and (type(value) ~= "number" or value < 0
        or value ~= math.floor(value)) then add("error", at .. "." .. key, key .. " 必须是非负整数") end
    end
    if type(schema.min_length) == "number" and type(schema.max_length) == "number"
      and schema.min_length > schema.max_length then add("error", at, "min_length 不能大于 max_length") end
    if schema.prefix ~= nil and (type(schema.prefix) ~= "string" or schema.prefix == "") then
      add("error", at .. ".prefix", "prefix 必须是非空字符串")
    end
    for _, key in ipairs({ "non_blank", "trimmed" }) do
      if schema[key] ~= nil and type(schema[key]) ~= "boolean" then
        add("error", at .. "." .. key, key .. " 必须是 boolean")
      end
    end
    if schema.format and not JsonValidator.formats[schema.format] then
      add("error", at .. ".format", "未知字符串 format：" .. tostring(schema.format))
    end
  end

  if type_has(schema, "number") or type_has(schema, "integer") then
    if schema.minimum ~= nil and type(schema.minimum) ~= "number" then
      add("error", at .. ".minimum", "minimum 必须是数字")
    end
    if schema.maximum ~= nil and type(schema.maximum) ~= "number" then
      add("error", at .. ".maximum", "maximum 必须是数字")
    end
    if type(schema.minimum) == "number" and type(schema.maximum) == "number"
      and schema.minimum > schema.maximum then add("error", at, "minimum 不能大于 maximum") end
  end
  if schema.enum ~= nil and not nonempty_array(schema.enum) then
    add("error", at .. ".enum", "enum 必须是非空数组")
  end
  if schema.contract ~= nil then
    add("error", at .. ".contract", "contract 业务钩子已移除；请使用可审计声明式策略")
  end
end

local function check_methods(rule, at, add)
  if not nonempty_array(rule.methods) then
    add("error", at .. ".methods", "methods 必须是非空数组；不得省略为任意方法")
    return
  end
  local seen = {}
  for _, method in ipairs(rule.methods) do
    if type(method) ~= "string" or method ~= method:upper() or not KNOWN_METHODS[method] then
      add("error", at .. ".methods", "method 必须是代理支持的大写 HTTP 方法")
    elseif seen[method] then
      add("warn", at .. ".methods", "存在重复 method：" .. method)
    end
    seen[method] = true
  end
end

local function check_media_types(values, at, add)
  if not nonempty_array(values) then
    add("error", at, "media_types 必须是非空数组")
    return
  end
  local seen = {}
  for _, value in ipairs(values) do
    if type(value) ~= "string" or value ~= value:lower()
      or not value:match("^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$") then
      add("error", at, "media type 必须是小写精确类型，不能使用通配符")
    elseif seen[value] then
      add("warn", at, "存在重复 media type：" .. value)
    end
    seen[value] = true
  end
end

local function check_header_rules(headers, at, add, response)
  if headers == nil then return end
  if type(headers) ~= "table" or is_array(headers) and next(headers) ~= nil then
    add("error", at, "headers 必须是按小写头名索引的 table")
    return
  end
  for name, policy in pairs(headers) do
    local header_at = at .. "." .. tostring(name)
    if not valid_header_name(name) then
      add("error", header_at, "请求头名称必须是小写 RFC token")
    elseif (response and FORBIDDEN_RESPONSE_HEADERS[name])
      or (not response and RESERVED_REQUEST_HEADERS[name]) then
      add("error", header_at, "该请求头由 WAF/Nginx 管理，不能在业务白名单中覆盖")
    end
    if type(policy) ~= "table" then
      add("error", header_at, "header 策略必须是 table")
    else
      check_known_keys(policy, KNOWN_HEADER_KEYS, header_at, add)
      if policy.required ~= nil and type(policy.required) ~= "boolean" then
        add("error", header_at .. ".required", "required 必须是 boolean")
      end
      check_schema(policy.schema, header_at .. ".schema", add)
      if not type_has(policy.schema, "string") then
        add("error", header_at .. ".schema", "header schema 必须声明 string")
      elseif not positive_integer(policy.schema.max_bytes)
        or policy.schema.max_bytes > 8192 then
        add("error", header_at .. ".schema.max_bytes", "header 必须配置不超过 8192 的 max_bytes")
      end
    end
  end
end

local function check_query_schema(schema, at, add)
  if type(schema) ~= "table" or not type_has(schema, "object") then
    add("error", at, "query_schema 必须引用 object schema")
    return
  end
  if schema.additional_properties ~= false then
    add("error", at .. ".additional_properties", "Query 必须 additional_properties=false")
  end
  for name, property in pairs(schema.properties or {}) do
    local wanted
    if property.type == "array" then
      wanted = type(property.items) == "table" and property.items.type or nil
      if property.max_items == nil then
        add("error", at .. ".properties." .. name .. ".max_items", "重复 Query 参数必须配置 max_items")
      end
    elseif type(property.type) == "string" then
      wanted = property.type
    elseif type(property.type) == "table" then
      for _, value in ipairs(property.type) do if value ~= "null" then wanted = value end end
    end
    if wanted ~= "string" and wanted ~= "integer" and wanted ~= "number" and wanted ~= "boolean" then
      add("error", at .. ".properties." .. name, "Query 只支持 string/integer/number/boolean 或其数组")
    end
  end
end

local function check_policies(policies, add)
  if type(policies) ~= "table" then add("error", "policies", "waf_policies.lua 必须返回 table") return end
  check_known_keys(policies, KNOWN_POLICY_CONFIG_KEYS, "policies", add)
  if policies.version ~= 2 then add("error", "policies.version", "策略配置 version 必须为 2") end
  if type(policies.timeout_profiles) ~= "table" then
    add("error", "policies.timeout_profiles", "timeout_profiles 必须是 table")
  else
    for name, enabled in pairs(policies.timeout_profiles) do
      if not PREDEFINED_TIMEOUTS[name] or enabled ~= true then
        add("error", "policies.timeout_profiles." .. tostring(name), "只允许启用 fast/standard/long")
      end
    end
    for name in pairs(PREDEFINED_TIMEOUTS) do
      if policies.timeout_profiles[name] ~= true then
        add("error", "policies.timeout_profiles." .. name, "必须启用预置超时档")
      end
    end
  end
  if type(policies.auth) ~= "table" or next(policies.auth) == nil then
    add("error", "policies.auth", "auth 必须至少定义一个策略")
  else
    for name, policy in pairs(policies.auth) do
      local at = "policies.auth." .. tostring(name)
      if type(name) ~= "string" or name == "" or not name:match("^[a-z][a-z0-9_]*$") then
        add("error", at, "认证策略名必须是小写标识符")
      end
      if type(policy) ~= "table" then
        add("error", at, "认证策略必须是 table")
      else
        check_known_keys(policy, KNOWN_AUTH_KEYS, at, add)
        if policy.mode ~= "none" and policy.mode ~= "bearer"
          and policy.mode ~= "api_key" and policy.mode ~= "basic" then
          add("error", at .. ".mode", "未知认证门禁模式")
        elseif policy.mode == "none" then
          if policy.header ~= nil or policy.max_bytes ~= nil then
            add("error", at, "mode=none 不能配置 header/max_bytes")
          end
        else
          if not valid_header_name(policy.header) then
            add("error", at .. ".header", "认证 header 必须是小写 RFC token")
          elseif (policy.mode == "bearer" or policy.mode == "basic")
            and policy.header ~= "authorization" then
            add("error", at .. ".header", "Bearer/Basic 只能使用 authorization")
          elseif policy.mode == "api_key" and RESERVED_REQUEST_HEADERS[policy.header]
            and policy.header ~= "x-api-key" then
            add("error", at .. ".header", "API Key 不能复用 WAF/Nginx 管理的请求头")
          end
          if not positive_integer(policy.max_bytes) or policy.max_bytes > 8192 then
            add("error", at .. ".max_bytes", "认证头上限必须为 1..8192 字节")
          end
        end
      end
    end
  end
  if type(policies.request_policies) ~= "table" then
    add("error", "policies.request_policies", "request_policies 必须是 table")
  else
    for name, policy in pairs(policies.request_policies) do
      local at = "policies.request_policies." .. tostring(name)
      if type(policy) ~= "table" then
        add("error", at, "请求策略必须是 table")
      else
        check_known_keys(policy, KNOWN_REQUEST_POLICY_KEYS, at, add)
        if policy.kind ~= "cypher_read_only" then add("error", at .. ".kind", "未知内置请求策略") end
        if type(policy.field) ~= "string" or not policy.field:match("^[A-Za-z_][A-Za-z0-9_]*$") then
          add("error", at .. ".field", "策略字段必须是 JSON 顶层字段名")
        end
      end
    end
  end
end

local function check_routes(routes, policies, whitelist, add)
  if type(routes) ~= "table" then add("error", "routes", "waf_routes.lua 必须返回 table") return end
  check_known_keys(routes, KNOWN_ROUTE_CONFIG_KEYS, "routes", add)
  if routes.version ~= 2 then add("error", "routes.version", "路由配置 version 必须为 2") end
  if not nonempty_array(routes.required_node_roles) then
    add("error", "routes.required_node_roles", "必须登记生产节点角色")
  end
  if type(routes.nodes) ~= "table" then add("error", "routes.nodes", "nodes 必须是 table") return end
  local used = {}
  for _, rule in ipairs(whitelist or {}) do used[rule.host] = true end
  for role, node_routes in pairs(routes.nodes) do
    local node_at = "routes.nodes." .. tostring(role)
    if type(role) ~= "string" or not role:match("^[a-z][a-z0-9_-]*$") then
      add("error", node_at, "节点角色名不合法")
    end
    if type(node_routes) ~= "table" then
      add("error", node_at, "节点路由必须是 table")
    else
      for host, route in pairs(node_routes) do
        local at = node_at .. "." .. tostring(host)
        if not valid_host(host) then add("error", at, "路由 Host 必须是小写精确主机名/IP") end
        if type(route) ~= "table" then
          add("error", at, "路由必须是 table")
        else
          check_known_keys(route, KNOWN_ROUTE_KEYS, at, add)
          if route.scheme ~= "http" then
            add("error", at .. ".scheme", "当前部署基线只允许固定 HTTP 下一跳")
          end
          if not valid_ipv4(route.address) then
            add("error", at .. ".address", "address 必须是固定规范 IPv4，不能使用域名/变量")
          end
          if not positive_integer(route.port) or route.port > 65535 then
            add("error", at .. ".port", "port 必须为 1..65535")
          end
          if not valid_host(route.upstream_host) then
            add("error", at .. ".upstream_host", "upstream_host 必须是精确 Host")
          end
          if not (policies and policies.timeout_profiles
            and policies.timeout_profiles[route.timeout_profile]) then
            add("error", at .. ".timeout_profile", "引用了不存在的超时档")
          end
        end
        -- 固定路由本身不会放行接口；允许提前登记，只有同时存在接口白名单才可达。
      end
    end
  end
  for _, role in ipairs(type(routes.required_node_roles) == "table"
    and routes.required_node_roles or {}) do
    local node_routes = routes.nodes[role]
    if type(node_routes) ~= "table" then
      add("error", "routes.nodes." .. tostring(role), "缺少必需生产节点路由")
    else
      for host in pairs(used) do
        if node_routes[host] == nil then
          add("error", "routes.nodes." .. role .. "." .. tostring(host),
            "该接口 Host 在生产节点缺少固定下一跳")
        end
      end
    end
  end
end

local function body_limit(config, transport, direction)
  local limits = config.limits or {}
  return limits["max_" .. (transport == "stream" and "stream" or "buffered")
    .. "_" .. direction .. "_body_bytes"]
end

local function check_body(body, at, add, config, transport, schemas, referenced, response)
  if type(body) ~= "table" then add("error", at, "body 策略必须是 table") return end
  check_known_keys(body, KNOWN_BODY_KEYS, at, add)
  local allowed_modes = response
    and { json = true, text = true, binary = true, empty = true, stream = true }
    or { json = true, text = true, binary = true }
  if not allowed_modes[body.mode] then add("error", at .. ".mode", "未知正文模式") return end
  if body.required ~= nil and type(body.required) ~= "boolean" then
    add("error", at .. ".required", "required 必须是 boolean")
  elseif response and body.required ~= nil then
    add("error", at .. ".required", "响应正文不使用 required")
  end
  if body.audit_body ~= nil and type(body.audit_body) ~= "boolean" then
    add("error", at .. ".audit_body", "audit_body 必须是 boolean")
  end

  if body.mode == "empty" then
    if not response then add("error", at .. ".mode", "请求不支持 empty 模式；不配置 body 即表示无正文") end
    for _, key in ipairs({ "media_types", "schema", "max_body_bytes" }) do
      if body[key] ~= nil then add("error", at .. "." .. key, "empty 响应不能配置 " .. key) end
    end
    return
  end
  if body.mode == "stream" and transport ~= "stream" then
    add("error", at .. ".mode", "stream 正文必须使用 transport=stream")
  elseif transport == "stream" and response and body.mode ~= "stream" then
    add("error", at .. ".mode", "流式路由的非空响应必须显式 mode=stream")
  end
  check_media_types(body.media_types, at .. ".media_types", add)
  local direction = response and "response" or "request"
  local limit = body_limit(config, transport, direction)
  if not positive_integer(body.max_body_bytes) then
    add("error", at .. ".max_body_bytes", "正文上限必须是大于 0 的整数")
  elseif positive_integer(limit) and body.max_body_bytes > limit then
    add("error", at .. ".max_body_bytes", "超过该 transport 的全局正文上限")
  end
  if body.mode == "json" or body.mode == "text" then
    if transport == "stream" and response then
      add("error", at .. ".mode", "流式响应不能声称执行 JSON/text 正文 schema 校验")
    end
    if type(body.schema) ~= "string" or schemas[body.schema] == nil then
      add("error", at .. ".schema", "必须引用存在的正文 schema")
    else
      referenced[body.schema] = true
      if body.mode == "text" and not type_has(schemas[body.schema], "string") then
        add("error", at .. ".schema", "text 正文必须引用 string schema")
      end
    end
  elseif body.schema ~= nil then
    add("error", at .. ".schema", "binary/stream 正文不支持 schema")
  end
end

function M.lint(config, routes, policies)
  local issues = {}
  local function add(level, where, message)
    issues[#issues + 1] = { level = level, where = where, msg = message }
  end

  check_policies(policies, add)
  if type(config) ~= "table" then add("error", "config", "规则文件必须返回 table") return issues end
  check_known_keys(config, KNOWN_CONFIG_KEYS, "config", add)
  if config.version ~= 2 then add("error", "config.version", "接口规则 version 必须为 2") end
  if type(config.limits) ~= "table" then
    add("error", "config.limits", "limits 必须是 table")
  else
    check_known_keys(config.limits, KNOWN_LIMIT_KEYS, "config.limits", add)
    for name, hard_limit in pairs(HARD_LIMITS) do
      local value = config.limits[name]
      if not positive_integer(value) then
        add("error", "config.limits." .. name, "必须是大于 0 的整数")
      elseif value > hard_limit then
        add("error", "config.limits." .. name, "超过 Nginx/V2 运行时硬上限 " .. hard_limit)
      end
    end
  end
  local whitelist = type(config.whitelist) == "table" and config.whitelist or {}
  local schemas = type(config.schemas) == "table" and config.schemas or {}
  if type(config.whitelist) ~= "table" or not is_array(config.whitelist) then
    add("error", "config.whitelist", "whitelist 必须是连续数组")
  elseif next(whitelist) == nil then
    add("warn", "config.whitelist", "白名单为空，所有请求都会被默认拒绝")
  end
  if type(config.schemas) ~= "table" then add("error", "config.schemas", "schemas 必须是 table") end

  local ids, seen_routes, referenced = {}, {}, {}
  for i, rule in ipairs(whitelist) do
    local at = "whitelist[" .. i .. "]"
    if type(rule) ~= "table" then add("error", at, "白名单规则必须是 table") rule = {} end
    check_known_keys(rule, KNOWN_RULE_KEYS, at, add)
    if type(rule.id) ~= "string" or not rule.id:match("^[A-Z0-9][A-Z0-9_-]*$") then
      add("error", at .. ".id", "规则 id 必须是稳定的大写标识符")
    elseif ids[rule.id] then add("error", at .. ".id", "白名单 id 重复：" .. rule.id) end
    ids[rule.id] = true
    if not valid_host(rule.host) then add("error", at .. ".host", "host 必须是小写精确主机名/IP") end
    check_methods(rule, at, add)
    if rule.transport ~= "buffered" and rule.transport ~= "stream" then
      add("error", at .. ".transport", "transport 必须为 buffered 或 stream")
    elseif rule.transport == "stream" then
      add("warn", at .. ".transport", "流式模式只校验状态/头/大小，无法在发送前校验完整响应正文")
    end
    if rule.timeout_profile ~= nil and not (policies and policies.timeout_profiles
      and policies.timeout_profiles[rule.timeout_profile]) then
      add("error", at .. ".timeout_profile", "引用了不存在的超时档")
    end
    if type(rule.auth_policy) ~= "string" or not (policies and policies.auth
      and policies.auth[rule.auth_policy]) then
      add("error", at .. ".auth_policy", "必须引用存在的认证门禁策略")
    end

    if (rule.path == nil) == (rule.path_template == nil) then
      add("error", at .. ".path", "必须且只能配置 path 或 path_template")
    elseif rule.path ~= nil then
      if type(rule.path) ~= "string" or rule.path:sub(1, 1) ~= "/"
        or rule.path:find("?", 1, true) or rule.path:find("#", 1, true)
        or rule.path:find("//", 1, true) or rule.path:find("%s")
        or rule.path:find("{", 1, true) or rule.path:find("}", 1, true) then
        add("error", at .. ".path", "path 必须是规范绝对精确路径")
      elseif reserved_internal_path(rule.path) then
        add("error", at .. ".path", "该前缀保留给 WAF 内部代理")
      end
      if rule.path_parameters ~= nil then
        add("error", at .. ".path_parameters", "精确 path 不能配置 path_parameters")
      end
    else
      local info = UrlFilter.path_template_info(rule.path_template)
      if not info then
        add("error", at .. ".path_template", "模板参数必须是独立命名路径段，如 {asset_id}")
      elseif reserved_internal_path(rule.path_template) then
        add("error", at .. ".path_template", "该前缀保留给 WAF 内部代理")
      else
        local definitions = type(rule.path_parameters) == "table" and rule.path_parameters or {}
        local expected = {}
        for _, name in ipairs(info.parameters) do
          expected[name] = true
          local schema = definitions[name]
          check_schema(schema, at .. ".path_parameters." .. name, add)
          if not type_has(schema, "string") then
            add("error", at .. ".path_parameters." .. name, "路径参数必须是 string schema")
          elseif schema.format == nil and schema.enum == nil then
            add("error", at .. ".path_parameters." .. name, "路径参数必须配置 format 或 enum")
          end
        end
        for name in pairs(definitions) do
          if not expected[name] then add("error", at .. ".path_parameters." .. tostring(name), "未被模板引用") end
        end
      end
    end
    if rule.request_schema ~= nil then add("error", at .. ".request_schema", "V1 字段已废弃；改用 request.body.schema") end
    if rule.pattern ~= nil then add("error", at .. ".pattern", "不得使用正则 path") end
    if rule.allow_query ~= nil then add("error", at .. ".allow_query", "V1 字段已废弃；改用 request.query_schema") end
    if rule.body ~= nil then add("error", at .. ".body", "V1 字段已废弃；改用 request.body") end

    for _, method in ipairs(type(rule.methods) == "table" and rule.methods or {}) do
      for _, seen in ipairs(seen_routes) do
        if seen.host == rule.host and seen.method == method and UrlFilter.paths_overlap(seen.rule, rule) then
          add("error", at, "host+method+path 重复或重叠，靠前规则会短路")
          break
        end
      end
      seen_routes[#seen_routes + 1] = { host = rule.host, method = method, rule = rule }
    end

    local request = rule.request
    if request ~= nil and type(request) ~= "table" then
      add("error", at .. ".request", "request 必须是 table")
      request = {}
    end
    request = request or {}
    check_known_keys(request, KNOWN_REQUEST_KEYS, at .. ".request", add)
    if request.query_schema ~= nil then
      if type(request.query_schema) ~= "string" or schemas[request.query_schema] == nil then
        add("error", at .. ".request.query_schema", "引用了不存在的 Query schema")
      else
        referenced[request.query_schema] = true
        check_query_schema(schemas[request.query_schema],
          "schemas." .. request.query_schema, add)
      end
    end
    check_header_rules(request.headers, at .. ".request.headers", add, false)
    if request.body ~= nil then
      check_body(request.body, at .. ".request.body", add, config,
        rule.transport, schemas, referenced, false)
    end
    if request.policies ~= nil then
      if not is_array(request.policies) then
        add("error", at .. ".request.policies", "policies 必须是数组")
      else
        for _, name in ipairs(request.policies) do
          if type(name) ~= "string" or not (policies and policies.request_policies
            and policies.request_policies[name]) then
            add("error", at .. ".request.policies", "引用了不存在的内置请求策略")
          end
        end
      end
    end

    if type(rule.responses) ~= "table" or next(rule.responses) == nil then
      add("error", at .. ".responses", "responses 必须登记至少一个状态码")
    else
      for status, response in pairs(rule.responses) do
        local response_at = at .. ".responses[" .. tostring(status) .. "]"
        if type(status) ~= "number" or status ~= math.floor(status) or status < 200 or status > 599 then
          add("error", response_at, "响应状态码必须是 200..599 整数")
        end
        if type(response) ~= "table" then
          add("error", response_at, "响应策略必须是 table")
        else
          check_known_keys(response, KNOWN_RESPONSE_KEYS, response_at, add)
          check_body(response.body, response_at .. ".body", add, config,
            rule.transport, schemas, referenced, true)
          check_header_rules(response.headers, response_at .. ".headers", add, true)
        end
      end
    end
  end

  for name, schema in pairs(schemas) do
    if type(name) ~= "string" or name == "" then add("error", "schemas", "schema 名称必须是非空字符串") end
    check_schema(schema, "schemas." .. tostring(name), add)
    if not referenced[name] then add("warn", "schemas." .. tostring(name), "schema 未被任何规则引用") end
  end
  check_routes(routes, policies, whitelist, add)
  return issues
end

function M.count(issues, level)
  local count = 0
  for _, issue in ipairs(issues or {}) do if issue.level == level then count = count + 1 end end
  return count
end

return M
