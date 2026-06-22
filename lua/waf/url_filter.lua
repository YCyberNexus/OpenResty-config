-- URL 过滤器：按规则列表匹配请求的 method + path，返回命中的规则或 nil。
-- 纯逻辑，不依赖 ngx，可单元测试。
local UrlFilter = {}
UrlFilter.__index = UrlFilter

-- regex_match: function(pattern, str) -> boolean
-- 生产环境注入基于 ngx.re 的 PCRE 实现；测试注入受控函数。
function UrlFilter.new(rules, regex_match)
  return setmetatable({ rules = rules or {}, regex_match = regex_match }, UrlFilter)
end

-- methods 省略视为不限 method；否则必须命中其一。
local function method_matches(rule, method)
  if not rule.methods then return true end
  for _, m in ipairs(rule.methods) do
    if m == method then return true end
  end
  return false
end

-- 规则用 path（精确）或 pattern（正则）二选一表达路径。
function UrlFilter:path_matches(rule, path)
  if rule.path ~= nil then
    return rule.path == path
  end
  if rule.pattern ~= nil then
    if not self.regex_match then
      error("url_filter: rule has a pattern but no regex engine was provided")
    end
    return self.regex_match(rule.pattern, path) and true or false
  end
  return false
end

function UrlFilter:match(method, path)
  for _, rule in ipairs(self.rules) do
    if self:path_matches(rule, path) and method_matches(rule, method) then
      return rule
    end
  end
  return nil
end

return UrlFilter
