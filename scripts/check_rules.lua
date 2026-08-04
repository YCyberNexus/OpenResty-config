#!/usr/bin/env luajit
-- V2 配置体检：同时检查接口契约、固定路由、认证/业务策略和正文硬上限。
--
-- 用法（在项目根目录执行）：
--   luajit scripts/check_rules.lua                 # 检查 conf/waf_rules.lua
--   luajit scripts/check_rules.lua conf/waf_rules.lua conf/waf_routes.lua conf/waf_policies.lua
--   luajit scripts/check_rules.lua --production conf/waf_rules.lua  # 兼容旧命令
--   # 服务器上用 OpenResty 自带的 luajit：
--   /data/openresty/luajit/bin/luajit scripts/check_rules.lua
-- 退出码：0=无 error；1=有 error；2=配置文件加载失败（多半是 Lua 语法错）。
local here = (arg and arg[0] or ""):gsub("[^/]*$", "")  -- scripts/ 目录
local root = here ~= "" and (here .. "../") or "./"
package.path = root .. "lua/?.lua;" .. root .. "conf/?.lua;" .. package.path

local lint = require("waf.rules_lint")

local paths = {}
for i = 1, #(arg or {}) do
  if arg[i] == "--production" then
    -- 兼容旧部署命令；简化版不再区分两套检查模式。
  elseif #paths < 3 then
    paths[#paths + 1] = arg[i]
  else
    io.stderr:write("用法：check_rules.lua [--production] [规则文件] [路由文件] [策略文件]\n")
    os.exit(2)
  end
end
local rules_path = paths[1] or (root .. "conf/waf_rules.lua")
local routes_path = paths[2] or (root .. "conf/waf_routes.lua")
local policies_path = paths[3] or (root .. "conf/waf_policies.lua")

local function load_config(path, label)
  local chunk, load_err = loadfile(path)
  if not chunk then
    io.stderr:write(label .. "加载失败：" .. tostring(load_err) .. "\n")
    os.exit(2)
  end
  local ok, value = pcall(chunk)
  if not ok then
    io.stderr:write(label .. "执行失败：" .. tostring(value) .. "\n")
    os.exit(2)
  end
  return value
end
local config = load_config(rules_path, "接口规则")
local routes = load_config(routes_path, "固定路由")
local policies = load_config(policies_path, "策略")

local issues = lint.lint(config, routes, policies)
for _, i in ipairs(issues) do
  local tag = i.level == "error" and "✗ ERROR" or "⚠ WARN "
  print(string.format("%s  %s  %s", tag, i.where, i.msg))
end

local errs = lint.count(issues, "error")
local warns = lint.count(issues, "warn")
print(string.format("\n体检完成：%d error，%d warning", errs, warns))
print(string.format("配置：%s + %s + %s", rules_path, routes_path, policies_path))
if type(config) == "table" then
  print(string.format("白名单条数：%d",
    type(config.whitelist) == "table" and #config.whitelist or 0))
  for _, rule in ipairs(type(config.whitelist) == "table" and config.whitelist or {}) do
    if type(rule) == "table" then
      local methods = type(rule.methods) == "table" and table.concat(rule.methods, ",") or "-"
      local statuses = {}
      for status in pairs(type(rule.responses) == "table" and rule.responses or {}) do
        statuses[#statuses + 1] = tostring(status)
      end
      table.sort(statuses)
      local request = rule.request or {}
      local body = request.body or {}
      print(string.format("  ALLOW  %s  %s  %s  [%s]  transport=%s  body=%s  query=%s  responses=%s", methods,
        tostring(rule.host or "-"), tostring(rule.path or rule.path_template or "-"),
        tostring(rule.id or "-"), tostring(rule.transport or "-"),
        tostring(body.schema or body.mode or "none"),
        tostring(request.query_schema or "none"), table.concat(statuses, ",")))
    end
  end
end
if errs == 0 then
  print("→ 静态检查通过。规则是否符合审批台账，仍须由运维使用对应业务验收用例确认。")
end
os.exit(errs > 0 and 1 or 0)
