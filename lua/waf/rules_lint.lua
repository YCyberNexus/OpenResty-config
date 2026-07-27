-- 运维规则静态体检：补足 openresty -t 无法发现的 schema 引用、URL 冲突和 fail-open 风险。
local JsonValidator = require("waf.json_validator")

local M = {}
local KNOWN_CONFIG_KEYS = {
  version = true,
  direction = true,
  example = true,
  max_request_body_bytes = true,
  max_response_body_bytes = true,
  whitelist = true,
  blacklist = true,
  forbidden_headers = true,
  schemas = true,
}
local KNOWN_WHITELIST_KEYS = {
  id = true,
  methods = true,
  path = true,
  request_schema = true,
  response_schemas = true,
  -- 保留这些旧/不安全关键字只为给出有针对性的迁移错误，而不是静默忽略。
  pattern = true,
  allow_query = true,
  body = true,
}
local KNOWN_BLACKLIST_KEYS = {
  methods = true,
  path = true,
  pattern = true,
}
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
    if schema.additional_properties ~= false then
      add("error", at .. ".additional_properties", "object 必须 additional_properties=false，未知字段不得放行")
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

function M.lint(config, opts)
  opts = opts or {}
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
  local blacklist = table_field("blacklist")
  local schemas = table_field("schemas")
  if type(config.whitelist) == "table" and not is_array(config.whitelist) then
    add("error", "whitelist", "whitelist 必须是连续数组")
  end
  if type(config.blacklist) == "table" and not is_array(config.blacklist) then
    add("error", "blacklist", "blacklist 必须是连续数组")
  end

  if type(config.direction) ~= "string" or config.direction == "" then
    add("error", "direction", "必须配置非空方向标识；具体方向由运维白名单台账决定")
  end
  if type(config.version) ~= "string" or config.version == "" then
    add("error", "version", "必须配置非空规则版本")
  end
  if config.example ~= nil and type(config.example) ~= "boolean" then
    add("error", "example", "example 只能是 boolean")
  end
  if opts.production then
    local version = tostring(config.version or "")
    if config.example == true or version:match("^EXAMPLE") then
      add("error", "example", "示例规则不能作为生产活动规则；请完成审批、更新版本并设置 example=false")
    end
    if version:match("^UNCONFIGURED") or config.direction == "not_configured" then
      add("error", "version", "生产部署前必须由运维填写正式规则版本和方向")
    end
    if config.example == nil then
      add("error", "example", "生产活动规则必须显式设置 example=false")
    end
  end
  for _, key in ipairs({ "max_request_body_bytes", "max_response_body_bytes" }) do
    if not positive_integer(config[key]) then
      add("error", key, key .. " 必须是大于 0 的整数")
    end
  end
  if positive_integer(config.max_request_body_bytes)
    and positive_integer(config.max_response_body_bytes)
    and config.max_response_body_bytes < config.max_request_body_bytes then
    add("warn", "max_response_body_bytes", "响应上限小于请求上限，请确认不是误配")
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
    if type(rule.path) ~= "string" or rule.path:sub(1, 1) ~= "/"
      or rule.path:find("?", 1, true) or rule.path:find("#", 1, true) then
      add("error", at .. ".path", "白名单必须使用不含 query/fragment 的绝对精确 path")
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
      local route_key = tostring(method) .. " " .. tostring(rule.path)
      if seen_routes[route_key] then
        add("error", at, "method+path 重复，靠前规则会短路：" .. route_key)
      else
        seen_routes[route_key] = true
      end
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

    if type(rule.response_schemas) ~= "table" or next(rule.response_schemas) == nil then
      add("error", at .. ".response_schemas", "每条 URL 必须显式登记允许的响应状态与 schema")
    else
      for status, schema_name in pairs(rule.response_schemas) do
        local numeric = tonumber(status)
        if type(status) ~= "string" or not numeric or numeric < 100 or numeric > 599
          or numeric ~= math.floor(numeric) or #status ~= 3 then
          add("error", at .. ".response_schemas", "响应状态键必须是三位字符串，如 \"200\"")
        end
        if type(schema_name) ~= "string" or schemas[schema_name] == nil then
          add("error", at .. ".response_schemas", "引用了不存在的响应 schema：" .. tostring(schema_name))
        else
          referenced[schema_name] = true
        end
      end
    end
  end

  for i, rule in ipairs(blacklist) do
    local at = "blacklist[" .. i .. "]"
    if type(rule) == "table" then check_known_keys(rule, KNOWN_BLACKLIST_KEYS, at, add) end
    if type(rule) ~= "table" or (rule.path == nil and rule.pattern == nil) then
      add("error", at, "黑名单规则必须有 path 或 pattern")
    elseif rule.path ~= nil and rule.pattern ~= nil then
      add("error", at, "黑名单 path 与 pattern 只能配置一个")
    elseif rule.path ~= nil and (type(rule.path) ~= "string" or rule.path:sub(1, 1) ~= "/") then
      add("error", at .. ".path", "黑名单 path 必须是绝对路径")
    elseif rule.pattern ~= nil and (type(rule.pattern) ~= "string" or rule.pattern == "") then
      add("error", at .. ".pattern", "黑名单 pattern 必须是非空字符串")
    elseif rule.methods ~= nil then
      check_methods(rule, at, add)
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

  local forbidden_headers = config.forbidden_headers
  if type(forbidden_headers) ~= "table" then
    add("error", "forbidden_headers", "forbidden_headers 必须是数组")
  elseif not is_array(forbidden_headers) then
    add("error", "forbidden_headers", "forbidden_headers 必须是连续数组")
  else
    for i, header in ipairs(forbidden_headers) do
      local at = "forbidden_headers[" .. i .. "]"
      if type(header) ~= "string" or header == "" or header == "*" then
        add("error", at, "请求头名必须是非空字符串，且不能是裸 *")
      elseif header ~= header:lower() then
        add("warn", at, "请求头名建议全部小写")
      elseif header:find("*", 1, true) and header:sub(-1) ~= "*" then
        add("error", at, "通配符只允许位于末尾做前缀匹配")
      end
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
