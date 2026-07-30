local json = require("spec.support.json")
local M = {}

function M.config()
  return assert(loadfile("conf/waf_rules_knowledge_example.lua"))()
end

function M.active_config()
  return assert(loadfile("conf/waf_rules.lua"))()
end

function M.same_path_config()
  return assert(loadfile("conf/waf_rules_same_path_example.lua"))()
end

function M.search_request(overrides)
  local value = { query = "机台发生通信异常时应该如何处理？", top_k = 5 }
  for key, item in pairs(overrides or {}) do value[key] = item end
  return value
end

function M.health_response(overrides)
  local value = {
    status = "ok",
    database = "ok",
    active_assets = 25,
    total_assets = 28,
    embedding_model = "BAAI/bge-base-zh-v1.5",
    embedding_dim = 768,
  }
  for key, item in pairs(overrides or {}) do value[key] = item end
  return value
end

function M.search_response(overrides)
  local value = {
    query = "机台发生通信异常时应该如何处理？",
    top_k = 5,
    retrieval_mode = "pgvector_active_versions_only",
    embedding_model = "BAAI/bge-base-zh-v1.5",
    results = json.array({}),
  }
  for key, item in pairs(overrides or {}) do value[key] = item end
  return value
end

M.json = json
return M
