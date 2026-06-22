-- 测试入口：`luajit spec/run.lua`（或 `make test`）
-- 自动发现并运行 spec/*_spec.lua
package.path = "./?.lua;./?/init.lua;./lua/?.lua;./lua/?/init.lua;" .. package.path

local helper = require("spec.helper")
helper.install()

local p = io.popen("ls spec/*_spec.lua 2>/dev/null")
local files = {}
if p then
  for line in p:lines() do files[#files + 1] = line end
  p:close()
end
table.sort(files)

for _, file in ipairs(files) do
  local mod = file:gsub("^spec/", "spec."):gsub("%.lua$", "")
  require(mod)
end

os.exit(helper.run() and 0 or 1)
