-- 精确 host + method + path 白名单匹配器；另支持以 UUID 结尾的受限路径模板。
local JsonValidator = require("waf.json_validator")

local UrlFilter = {}
UrlFilter.__index = UrlFilter

local UUID_TOKEN = "{uuid}"

function UrlFilter.new(rules)
  return setmetatable({ rules = rules or {} }, UrlFilter)
end

local function method_matches(rule, method)
  for _, allowed in ipairs(rule.methods or {}) do
    if allowed == method then return true end
  end
  return false
end

-- 路径模板只允许一个位于末尾、占满整个路径段的 {uuid}，不接受任意正则。
-- 例如：/ai/knowledge/assets/{uuid}。
function UrlFilter.path_template_prefix(template)
  if type(template) ~= "string" or template:sub(-#UUID_TOKEN) ~= UUID_TOKEN then return nil end
  local prefix = template:sub(1, #template - #UUID_TOKEN)
  if prefix:sub(1, 1) ~= "/" or prefix:sub(-1) ~= "/"
    or prefix:find("?", 1, true) or prefix:find("#", 1, true)
    or prefix:find("{", 1, true) or prefix:find("}", 1, true)
    or prefix:find("//", 1, true) or prefix:find("%s") then
    return nil
  end
  for segment in prefix:gmatch("[^/]+") do
    if segment == "." or segment == ".." then return nil end
  end
  return prefix
end

function UrlFilter.path_matches(rule, path)
  if type(path) ~= "string" then return false end
  if rule.path ~= nil then return rule.path == path end

  local prefix = UrlFilter.path_template_prefix(rule.path_template)
  if not prefix or path:sub(1, #prefix) ~= prefix then return false end
  local parameter = path:sub(#prefix + 1)
  return JsonValidator.formats.uuid(parameter)
end

-- 静态体检用于拒绝会相互短路的精确路径/UUID 模板组合。
function UrlFilter.paths_overlap(left, right)
  if left.path ~= nil and right.path ~= nil then return left.path == right.path end
  if left.path ~= nil then return UrlFilter.path_matches(right, left.path) end
  if right.path ~= nil then return UrlFilter.path_matches(left, right.path) end

  local left_prefix = UrlFilter.path_template_prefix(left.path_template)
  local right_prefix = UrlFilter.path_template_prefix(right.path_template)
  return left_prefix ~= nil and left_prefix == right_prefix
end

function UrlFilter:match(host, method, path)
  for _, rule in ipairs(self.rules) do
    if rule.host == host and UrlFilter.path_matches(rule, path) and method_matches(rule, method) then
      return rule
    end
  end
  return nil
end

return UrlFilter
