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

function M.search_result(overrides)
  local value = {
    asset_id = "f440c18e-a281-44bc-a878-8aa92b620879",
    asset_key = "equipment/ASML_manual.pdf",
    asset_name = "ASML_manual.pdf",
    version_id = "e8b85a47-9b58-49d0-8711-17de3df5ea87",
    version_no = 2,
    chunk_id = 10235,
    chunk_index = 36,
    content = "发生通信异常后，首先检查设备网络连接状态……",
    page_number = 18,
    section_title = "通信异常处理",
    metadata = { source = "/source_docs/equipment/ASML_manual.pdf", page = 17 },
    distance = 0.1847,
    vector_score = 0.8153,
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
    results = json.array({ M.search_result() }),
  }
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

function M.regex_match(pattern, value)
  return string.find(value, pattern) ~= nil
end

M.json = json
return M
