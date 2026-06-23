#!/usr/bin/env luajit
-- 配置体检：加载 waf_rules 配置并跑静态检查，补 `openresty -t` 抓不到的盲区
-- （body 引用不存在的 schema / allowed_fields 漏 model,messages / max_* 没配数字 等）。
--
-- 用法（在项目根目录执行）：
--   luajit scripts/check_rules.lua                 # 检查 conf/waf_rules.lua
--   luajit scripts/check_rules.lua conf/waf_rules.lua
--   # 服务器上用 OpenResty 自带的 luajit：
--   /usr/local/openresty/luajit/bin/luajit scripts/check_rules.lua
-- 退出码：0=无 error；1=有 error；2=配置文件加载失败（多半是 Lua 语法错）。
local here = (arg and arg[0] or ""):gsub("[^/]*$", "")  -- scripts/ 目录
local root = here ~= "" and (here .. "../") or "./"
package.path = root .. "lua/?.lua;" .. root .. "conf/?.lua;" .. package.path

local lint = require("waf.rules_lint")

local path = (arg and arg[1]) or (root .. "conf/waf_rules.lua")

local chunk, load_err = loadfile(path)
if not chunk then
  io.stderr:write("加载失败（多半是 Lua 语法错）：" .. tostring(load_err) .. "\n")
  os.exit(2)
end

local ok, config = pcall(chunk)
if not ok then
  io.stderr:write("执行配置返回出错：" .. tostring(config) .. "\n")
  os.exit(2)
end

local issues = lint.lint(config)
for _, i in ipairs(issues) do
  local tag = i.level == "error" and "[31m✗ ERROR[0m" or "[33m⚠ WARN [0m"
  print(string.format("%s  %s  %s", tag, i.where, i.msg))
end

local errs = lint.count(issues, "error")
local warns = lint.count(issues, "warn")
print(string.format("\n体检完成：%d error，%d warning（检查的是 %s）", errs, warns, path))
if errs == 0 then
  print("→ 静态检查通过。注意：引用一致性已查，但规则是否“符合业务意图”仍需跑 scripts/smoke.sh 实测。")
end
os.exit(errs > 0 and 1 or 0)
