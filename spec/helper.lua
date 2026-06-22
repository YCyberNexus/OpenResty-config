-- 极简 busted 风格测试框架（纯 LuaJIT 可跑，无需 luarocks/busted）
-- 写法与 busted 兼容：describe / it / before_each / assert.are.same 等。
-- 将来装了真 busted，可直接用 `busted spec/` 运行同样的 spec，无需改测试。
local _assert = assert

local M = {}

local suites = {}
local current_suite = nil

function M.describe(name, fn)
  local suite = { name = name, tests = {}, before_each = {} }
  local prev = current_suite
  current_suite = suite
  fn()
  current_suite = prev
  suites[#suites + 1] = suite
end

function M.it(name, fn)
  _assert(current_suite, "it() must be inside describe()")
  current_suite.tests[#current_suite.tests + 1] = { name = name, fn = fn }
end

function M.before_each(fn)
  _assert(current_suite, "before_each() must be inside describe()")
  current_suite.before_each[#current_suite.before_each + 1] = fn
end

local function deepeq(a, b)
  if a == b then return true end
  if type(a) ~= "table" or type(b) ~= "table" then return false end
  for k, v in pairs(a) do
    if not deepeq(v, b[k]) then return false end
  end
  for k in pairs(b) do
    if a[k] == nil then return false end
  end
  return true
end

local function serialize(v)
  if type(v) == "table" then
    local parts = {}
    for k, val in pairs(v) do
      parts[#parts + 1] = tostring(k) .. "=" .. serialize(val)
    end
    table.sort(parts)
    return "{" .. table.concat(parts, ", ") .. "}"
  end
  if type(v) == "string" then return '"' .. v .. '"' end
  return tostring(v)
end

local function fail(msg) error(msg, 3) end

local are = {
  same = function(exp, got)
    if not deepeq(exp, got) then fail("expected " .. serialize(exp) .. " but got " .. serialize(got)) end
  end,
  equal = function(exp, got)
    if exp ~= got then fail("expected " .. serialize(exp) .. " but got " .. serialize(got)) end
  end,
}

M.assert = setmetatable({
  are = are,
  same = are.same,
  equals = are.equal,
  equal = are.equal,
  is_true = function(v) if v ~= true then fail("expected true but got " .. serialize(v)) end end,
  is_false = function(v) if v ~= false then fail("expected false but got " .. serialize(v)) end end,
  is_nil = function(v) if v ~= nil then fail("expected nil but got " .. serialize(v)) end end,
  is_not_nil = function(v) if v == nil then fail("expected non-nil but got nil") end end,
  truthy = function(v) if not v then fail("expected truthy but got " .. serialize(v)) end end,
  falsy = function(v) if v then fail("expected falsy but got " .. serialize(v)) end end,
}, {
  __call = function(_, cond, msg) if not cond then fail(msg or "assertion failed") end return cond end,
})

function M.install()
  _G.describe = M.describe
  _G.it = M.it
  _G.before_each = M.before_each
  _G.assert = M.assert
end

function M.run()
  local pass, failed = 0, 0
  local failures = {}
  for _, suite in ipairs(suites) do
    print("\n● " .. suite.name)
    for _, t in ipairs(suite.tests) do
      local ok, err = pcall(function()
        for _, b in ipairs(suite.before_each) do b() end
        t.fn()
      end)
      if ok then
        pass = pass + 1
        print("  \27[32m✓\27[0m " .. t.name)
      else
        failed = failed + 1
        failures[#failures + 1] = suite.name .. " › " .. t.name .. "\n      " .. tostring(err)
        print("  \27[31m✗\27[0m " .. t.name)
      end
    end
  end
  print(string.format("\n%d passed, %d failed", pass, failed))
  if failed > 0 then
    print("\nFailures:")
    for _, f in ipairs(failures) do print("  " .. f) end
  end
  return failed == 0
end

return M
