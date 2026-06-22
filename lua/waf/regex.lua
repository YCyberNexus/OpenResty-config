-- 生产环境的正则匹配实现：基于 ngx.re（PCRE）。
-- "jo" = JIT 编译 + 编译结果缓存（配合 lua_regex_cache_max_entries 常驻）。
-- 仅在 OpenResty 运行时可用；纯 LuaJIT 测试通过依赖注入绕过它。
local _M = {}

function _M.match(pattern, str)
  if str == nil then return false end
  local from = ngx.re.find(str, pattern, "jo")
  return from ~= nil
end

return _M
