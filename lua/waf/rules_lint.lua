-- 运维规则静态体检：补足 openresty -t 无法发现的 schema 引用、URL 冲突和 fail-open 风险。
local JsonValidator = require("waf.json_validator")
local UrlFilter = require("waf.url_filter")

local M = {}
local KNOWN_CONFIG_KEYS = {
  max_request_body_bytes = true,
  max_response_body_bytes = true,
  whitelist = true,
  schemas = true,
}
local KNOWN_WHITELIST_KEYS = {
  id = true,
  host = true,
  methods = true,
  path = true,
  path_template = true,
  request_schema = true,
  responses = true,
  -- 保留这些旧/不安全关键字只为给出有针对性的迁移错误，而不是静默忽略。
  pattern = true,
  allow_query = true,
  body = true,
}
local KNOWN_RESPONSE_KEYS = {
  schema = true,
  max_body_bytes = true,
}
local MAX_REQUEST_BODY_BYTES = 131072
local MAX_RESPONSE_BODY_BYTES = 1048576
local KNOWN_METHODS = {
  GET = true, POST = true, PUT = true, PATCH = true, DELETE = true,
}
local KNOWN_TYPES = {
  object = true, array = true, string = true, integer = true,
  number = true, boolean = true, ["null"] = true,
}
local KNOWN_SCHEMA_KEYS = {
  type = true,
  required = true,
  properties = true,
  additional_properties = true,
  max_properties = true,
  items = true,
  min_items = true,
  max_items = true,
  min_length = true,
  max_length = true,
  max_bytes = true,
  non_blank = true,
  trimmed = true,
  prefix = true,
  format = true,
  minimum = true,
  maximum = true,
  enum = true,
  contract = true,
}

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

local function valid_host(value)
  if type(value) ~= "string" or value == "" or #value > 253 or value ~= value:lower()
    or value:find(":", 1, true) or value:find("/", 1, true)
    or value:find("%s") or value:find("%.%.")
    or value:sub(1, 1) == "." or value:sub(-1) == "." then
    return false
  end
  for label in value:gmatch("[^.]+") do
    if #label > 63 or not label:match("^[a-z0-9][a-z0-9-]*[a-z0-9]$") then
      if not label:match("^[a-z0-9]$") then return false end
    end
  end
  return true
end

local function type_has(schema, wanted)
  if schema.type == wanted then return true end
  if type(schema.type) == "table" then
    for _, value in ipairs(schema.type) do
      if value == wanted then return true end
    end
  end
  return false
end

local function check_known_keys(value, known, at, add)
  for key in pairs(value or {}) do
    if type(key) ~= "string" or not known[key] then
      add("error", at .. "." .. tostring(key), "未知配置关键字；可能是拼写错误")
    end
  end
end

local function check_methods(rule, at, add)
  if not nonempty_array(rule.methods) then
    add("error", at .. ".methods", "methods 必须是非空数组；跨区白名单不得省略为任意方法")
    return
  end
  local seen = {}
  for _, method in ipairs(rule.methods) do
    if type(method) ~= "string" or method ~= method:upper() or not KNOWN_METHODS[method] then
      add("error", at .. ".methods", "method 必须是当前代理支持的大写 HTTP 方法")
    elseif seen[method] then
      add("warn", at .. ".methods", "存在重复 method：" .. method)
    else
      seen[method] = true
    end
  end
end

local function schema_types(schema, at, add)
  local declared = schema.type
  if type(declared) == "string" then
    if not KNOWN_TYPES[declared] then add("error", at .. ".type", "未知 JSON 类型：" .. declared) end
    return
  end
  if not nonempty_array(declared) then
    add("error", at .. ".type", "type 必须是类型名或非空类型数组")
    return
  end
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

local function check_schema(schema, at, add)
  if type(schema) ~= "table" then
    add("error", at, "schema 必须是 table")
    return
  end
  for key in pairs(schema) do
    if type(key) ~= "string" or not KNOWN_SCHEMA_KEYS[key] then
      add("error", at .. "." .. tostring(key), "未知 schema 关键字；可能是拼写错误")
    end
  end
  schema_types(schema, at, add)

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
      for _, key in ipairs(schema.required or {}) do
        if type(key) ~= "string" or properties[key] == nil then
          add("error", at .. ".required", "required 引用了未定义字段：" .. tostring(key))
        end
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
    required = type_has(schema, "object"),
    properties = type_has(schema, "object"),
    additional_properties = type_has(schema, "object"),
    max_properties = type_has(schema, "object"),
    items = type_has(schema, "array"),
    min_items = type_has(schema, "array"),
    max_items = type_has(schema, "array"),
    min_length = type_has(schema, "string"),
    max_length = type_has(schema, "string"),
    max_bytes = type_has(schema, "string"),
    non_blank = type_has(schema, "string"),
    trimmed = type_has(schema, "string"),
    prefix = type_has(schema, "string"),
    format = type_has(schema, "string"),
    minimum = type_has(schema, "number") or type_has(schema, "integer"),
    maximum = type_has(schema, "number") or type_has(schema, "integer"),
  }
  for key, applies in pairs(applicability) do
    if schema[key] ~= nil and not applies then
      add("error", at .. "." .. key, key .. " 与声明的 JSON 类型不匹配，运行时不会应用")
    end
  end

  if type_has(schema, "array") then
    if type(schema.items) ~= "table" then
      add("error", at .. ".items", "array 必须配置 items schema")
    else
      check_schema(schema.items, at .. ".items", add)
    end
    if schema.min_items ~= nil and (type(schema.min_items) ~= "number"
      or schema.min_items < 0 or schema.min_items ~= math.floor(schema.min_items)) then
      add("error", at .. ".min_items", "min_items 必须是非负整数")
    end
    if schema.max_items ~= nil and (type(schema.max_items) ~= "number"
      or schema.max_items < 0 or schema.max_items ~= math.floor(schema.max_items)) then
      add("error", at .. ".max_items", "max_items 必须是非负整数")
    end
    if type(schema.min_items) == "number" and type(schema.max_items) == "number"
      and schema.min_items > schema.max_items then
      add("error", at, "min_items 不能大于 max_items")
    end
  end

  if type_has(schema, "string") then
    for _, key in ipairs({ "min_length", "max_length", "max_bytes" }) do
      local value = schema[key]
      if value ~= nil and (type(value) ~= "number" or value < 0 or value ~= math.floor(value)) then
        add("error", at .. "." .. key, key .. " 必须是非负整数")
      end
    end
    if type(schema.min_length) == "number" and type(schema.max_length) == "number"
      and schema.min_length > schema.max_length then
      add("error", at, "min_length 不能大于 max_length")
    end
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
      and schema.minimum > schema.maximum then
      add("error", at, "minimum 不能大于 maximum")
    end
  end

  if schema.enum ~= nil and not nonempty_array(schema.enum) then
    add("error", at .. ".enum", "enum 必须是非空数组")
  end
  if schema.contract ~= nil then
    add("error", at .. ".contract", "contract 业务钩子已移除；请使用运维可审计的声明式 schema")
  end
end

function M.lint(config)
  local issues = {}
  local function add(level, where, message)
    issues[#issues + 1] = { level = level, where = where, msg = message }
  end

  if type(config) ~= "table" then
    add("error", "config", "规则文件必须返回 table")
    return issues
  end
  check_known_keys(config, KNOWN_CONFIG_KEYS, "config", add)

  local function table_field(name)
    if type(config[name]) ~= "table" then
      add("error", name, name .. " 必须是 table")
      return {}
    end
    return config[name]
  end

  local whitelist = table_field("whitelist")
  local schemas = table_field("schemas")
  if type(config.whitelist) == "table" and not is_array(config.whitelist) then
    add("error", "whitelist", "whitelist 必须是连续数组")
  end
  if not positive_integer(config.max_request_body_bytes) then
    add("error", "max_request_body_bytes", "max_request_body_bytes 必须是大于 0 的整数")
  elseif config.max_request_body_bytes > MAX_REQUEST_BODY_BYTES then
    add("error", "max_request_body_bytes", "不得超过 Nginx client_max_body_size 的 131072 字节")
  end
  if not positive_integer(config.max_response_body_bytes) then
    add("error", "max_response_body_bytes", "max_response_body_bytes 必须是大于 0 的整数")
  elseif config.max_response_body_bytes > MAX_RESPONSE_BODY_BYTES then
    add("error", "max_response_body_bytes",
      "不得超过 Nginx subrequest_output_buffer_size 的 1048576 字节")
  end

  if not nonempty_array(whitelist) then
    add("warn", "whitelist", "白名单为空，所有请求都会被默认拒绝")
  end

  local ids, seen_routes, referenced = {}, {}, {}
  for i, rule in ipairs(whitelist) do
    local at = "whitelist[" .. i .. "]"
    if type(rule) ~= "table" then
      add("error", at, "白名单规则必须是 table")
      rule = {}
    end
    check_known_keys(rule, KNOWN_WHITELIST_KEYS, at, add)
    if type(rule.id) ~= "string" or rule.id == "" then
      add("error", at .. ".id", "每条白名单必须有稳定非空 id")
    elseif ids[rule.id] then
      add("error", at .. ".id", "白名单 id 重复：" .. rule.id)
    else
      ids[rule.id] = true
    end
    if not valid_host(rule.host) then
      add("error", at .. ".host", "host 必须是不含端口、通配符和路径的小写精确主机名或 IPv4 地址")
    end
    if (rule.path == nil) == (rule.path_template == nil) then
      add("error", at .. ".path", "必须且只能配置 path 或 path_template 其中一个")
    elseif rule.path ~= nil then
      if type(rule.path) ~= "string" or rule.path:sub(1, 1) ~= "/"
        or rule.path:find("?", 1, true) or rule.path:find("#", 1, true) then
        add("error", at .. ".path", "path 必须是不含 query/fragment 的绝对精确路径")
      elseif rule.path == "/__waf_upstream" or rule.path:sub(1, 16) == "/__waf_upstream/" then
        add("error", at .. ".path", "该前缀保留给 WAF 内部响应校验子请求，不得登记为业务 path")
      end
    else
      local prefix = UrlFilter.path_template_prefix(rule.path_template)
      if not prefix then
        add("error", at .. ".path_template",
          "path_template 只支持以独立 {uuid} 路径段结尾的绝对路径")
      elseif prefix == "/__waf_upstream/" or prefix:sub(1, 16) == "/__waf_upstream/" then
        add("error", at .. ".path_template",
          "该前缀保留给 WAF 内部响应校验子请求，不得登记为业务 path")
      end
    end
    if rule.pattern ~= nil then
      add("error", at .. ".pattern", "跨区生产白名单不得使用正则 path；必须逐条精确登记")
    end
    check_methods(rule, at, add)
    if rule.allow_query ~= nil then
      add("error", at .. ".allow_query", "当前版本不支持 query 参数 schema，不能开启任意 query 放行")
    end
    if rule.body ~= nil then
      add("error", at .. ".body", "旧 body 配置已废弃，请使用 request_schema")
    end

    local methods = type(rule.methods) == "table" and rule.methods or {}
    for _, method in ipairs(methods) do
      for _, seen in ipairs(seen_routes) do
        if seen.host == rule.host and seen.method == method
          and UrlFilter.paths_overlap(seen.rule, rule) then
          local route = tostring(rule.path or rule.path_template)
          add("error", at, "host+method+path 重复或重叠，靠前规则会短路："
            .. tostring(rule.host) .. " " .. tostring(method) .. " " .. route)
          break
        end
      end
      seen_routes[#seen_routes + 1] = { host = rule.host, method = method, rule = rule }
    end
    if rule.request_schema ~= nil then
      if type(rule.request_schema) ~= "string" or rule.request_schema == "" then
        add("error", at .. ".request_schema", "request_schema 必须是非空 schema 名称")
      elseif schemas[rule.request_schema] == nil then
        add("error", at .. ".request_schema", "引用了不存在的 schema：" .. tostring(rule.request_schema))
      else
        referenced[rule.request_schema] = true
      end
    end

    if type(rule.responses) ~= "table" or next(rule.responses) == nil then
      add("error", at .. ".responses", "responses 必须按 HTTP 状态码登记至少一个响应 schema")
    else
      for status, policy in pairs(rule.responses) do
        local response_at = at .. ".responses[" .. tostring(status) .. "]"
        if type(status) ~= "number" or status ~= math.floor(status)
          or status < 100 or status > 599 then
          add("error", response_at, "响应状态码必须是 100 到 599 的整数")
        end
        if type(policy) ~= "table" then
          add("error", response_at, "响应策略必须是 table")
        else
          check_known_keys(policy, KNOWN_RESPONSE_KEYS, response_at, add)
          if type(policy.schema) ~= "string" or policy.schema == "" then
            add("error", response_at .. ".schema", "响应 schema 必须是非空名称")
          elseif schemas[policy.schema] == nil then
            add("error", response_at .. ".schema", "引用了不存在的 schema：" .. tostring(policy.schema))
          else
            referenced[policy.schema] = true
          end
          if not positive_integer(policy.max_body_bytes) then
            add("error", response_at .. ".max_body_bytes", "响应体上限必须是大于 0 的整数")
          elseif positive_integer(config.max_response_body_bytes)
            and policy.max_body_bytes > config.max_response_body_bytes then
            add("error", response_at .. ".max_body_bytes", "不得超过全局 max_response_body_bytes")
          end
        end
      end
    end

  end

  for name, schema in pairs(schemas) do
    if type(name) ~= "string" or name == "" then
      add("error", "schemas", "schema 名称必须是非空字符串")
    end
    check_schema(schema, "schemas." .. tostring(name), add)
    if not referenced[name] then
      add("warn", "schemas." .. tostring(name), "schema 未被任何请求或响应规则引用")
    end
  end

  return issues
end

function M.count(issues, level)
  local count = 0
  for _, issue in ipairs(issues or {}) do
    if issue.level == level then count = count + 1 end
  end
  return count
end

return M
