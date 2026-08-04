-- V2 精确 host + method + path 白名单匹配器。
-- 路径模板只允许占满整个路径段的命名参数，例如 /users/{user_id}/files/{file_id}；
-- 参数值必须通过该规则 path_parameters 中的声明式 string schema。
local JsonValidator = require("waf.json_validator")

local UrlFilter = {}
UrlFilter.__index = UrlFilter

local function split_path(path)
  if type(path) ~= "string" or path:sub(1, 1) ~= "/" then return nil end
  if path ~= "/" and path:sub(-1) == "/" then return nil end
  if path:find("//", 1, true) or path:find("?", 1, true)
    or path:find("#", 1, true) or path:find("%s") then return nil end
  local parts = {}
  for segment in path:gmatch("[^/]+") do
    if segment == "." or segment == ".." then return nil end
    parts[#parts + 1] = segment
  end
  return parts
end

local function placeholder(segment)
  return type(segment) == "string"
    and segment:match("^%{([a-z][a-z0-9_]*)%}$") or nil
end

function UrlFilter.path_template_info(template)
  local segments = split_path(template)
  if not segments then return nil end
  local names, seen, count = {}, {}, 0
  for i, segment in ipairs(segments) do
    local name = placeholder(segment)
    if name then
      if seen[name] then return nil end
      seen[name] = true
      names[#names + 1] = name
      count = count + 1
    elseif segment:find("{", 1, true) or segment:find("}", 1, true) then
      return nil
    end
    segments[i] = { literal = name == nil and segment or nil, parameter = name }
  end
  if count == 0 then return nil end
  return { segments = segments, parameters = names }
end

-- 兼容旧调用方；V2 模板不再局限于末尾 UUID。
function UrlFilter.path_template_prefix(template)
  local info = UrlFilter.path_template_info(template)
  if not info or #info.parameters ~= 1 then return nil end
  local last = info.segments[#info.segments]
  if not last or not last.parameter then return nil end
  return template:sub(1, #template - #(last.parameter) - 2)
end

local function method_matches(rule, method)
  for _, allowed in ipairs(rule.methods or {}) do
    if allowed == method then return true end
  end
  return false
end

local function parameter_matches(rule, name, value)
  local schema = rule.path_parameters and rule.path_parameters[name]
  if type(schema) ~= "table" then return false end
  return JsonValidator.new(schema):validate(value)
end

function UrlFilter.path_matches(rule, path)
  if type(path) ~= "string" then return false end
  if rule.path ~= nil then return rule.path == path, {} end

  local info = UrlFilter.path_template_info(rule.path_template)
  local values = split_path(path)
  if not info or not values or #values ~= #info.segments then return false end
  local params = {}
  for i, segment in ipairs(info.segments) do
    local value = values[i]
    if segment.literal then
      if value ~= segment.literal then return false end
    elseif not parameter_matches(rule, segment.parameter, value) then
      return false
    else
      params[segment.parameter] = value
    end
  end
  return true, params
end

local function enum_values(schema)
  if type(schema) ~= "table" or type(schema.enum) ~= "table" then return nil end
  local result = {}
  for _, value in ipairs(schema.enum) do
    if type(value) ~= "string" then return nil end
    result[value] = true
  end
  return result
end

local function parameters_may_overlap(left_schema, right_schema)
  local left_enum, right_enum = enum_values(left_schema), enum_values(right_schema)
  if left_enum and right_enum then
    for value in pairs(left_enum) do
      if right_enum[value] then return true end
    end
    return false
  end
  return true -- 无法证明互斥时按可能重叠处理，保持 fail-closed。
end

local function route_segments(rule)
  if rule.path ~= nil then
    local parts = split_path(rule.path)
    if not parts then return nil end
    local result = {}
    for i, value in ipairs(parts) do result[i] = { literal = value } end
    return result
  end
  local info = UrlFilter.path_template_info(rule.path_template)
  return info and info.segments or nil
end

-- 静态体检用于拒绝会相互短路的精确路径/模板组合。
function UrlFilter.paths_overlap(left, right)
  local left_segments, right_segments = route_segments(left), route_segments(right)
  if not left_segments or not right_segments or #left_segments ~= #right_segments then
    return false
  end
  for i = 1, #left_segments do
    local a, b = left_segments[i], right_segments[i]
    if a.literal and b.literal then
      if a.literal ~= b.literal then return false end
    elseif a.literal then
      if not parameter_matches(right, b.parameter, a.literal) then return false end
    elseif b.literal then
      if not parameter_matches(left, a.parameter, b.literal) then return false end
    elseif not parameters_may_overlap(
      left.path_parameters and left.path_parameters[a.parameter],
      right.path_parameters and right.path_parameters[b.parameter]) then
      return false
    end
  end
  return true
end

function UrlFilter.new(rules)
  return setmetatable({ rules = rules or {} }, UrlFilter)
end

function UrlFilter:match(host, method, path)
  for _, rule in ipairs(self.rules) do
    if rule.host == host and method_matches(rule, method) then
      local matched, params = UrlFilter.path_matches(rule, path)
      if matched then return rule, params end
    end
  end
  return nil
end

return UrlFilter
