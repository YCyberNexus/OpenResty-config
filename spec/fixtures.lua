local json = require("spec.support.json")
local M = {}

function M.config()
  return assert(loadfile("conf/waf_rules_knowledge_example.lua"))()
end

function M.active_config()
  return assert(loadfile("conf/waf_rules.lua"))()
end

function M.search_request(overrides)
  local value = { query = "机台发生通信异常时应该如何处理？", top_k = 5 }
  for key, item in pairs(overrides or {}) do value[key] = item end
  return value
end

M.json = json
return M
