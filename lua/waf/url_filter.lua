-- 精确 host + method + path 白名单匹配器。
local UrlFilter = {}
UrlFilter.__index = UrlFilter

function UrlFilter.new(rules)
  return setmetatable({ rules = rules or {} }, UrlFilter)
end

local function method_matches(rule, method)
  for _, allowed in ipairs(rule.methods or {}) do
    if allowed == method then return true end
  end
  return false
end

function UrlFilter:match(host, method, path)
  for _, rule in ipairs(self.rules) do
    if rule.host == host and rule.path == path and method_matches(rule, method) then
      return rule
    end
  end
  return nil
end

return UrlFilter
