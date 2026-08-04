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

function M.active_search_request(overrides)
  local value = {
    query = "ASML 通信异常怎么排查",
    top_k = 5,
  }
  for key, item in pairs(overrides or {}) do value[key] = item end
  return value
end

function M.active_search_response(overrides)
  local value = {
    query = "ASML 通信异常怎么排查",
    top_k = 5,
    retrieval_mode = "pgvector_active_versions_only",
    embedding_model = "BAAI/bge-base-zh-v1.5",
    results = json.array({
      {
        asset_id = "f440c18e-a281-44bc-a878-8aa92b620879",
        asset_key = "unclassified/ASML_XT-1060K_SECS_manual_51146.pdf",
        asset_name = "ASML_XT-1060K_SECS_manual_51146.pdf",
        version_id = "e8b85a47-9b58-49d0-8711-17de3df5ea87",
        version_no = 2,
        chunk_id = 123,
        chunk_index = 15,
        content = "命中的 chunk 文本内容",
        page_number = 12,
        section_title = "章节标题",
        metadata = {},
        distance = 0.18,
        vector_score = 0.82,
      },
    }),
  }
  for key, item in pairs(overrides or {}) do value[key] = item end
  return value
end

function M.asset_response(overrides)
  local version = {
    version_id = "e8b85a47-9b58-49d0-8711-17de3df5ea87",
    version_no = 2,
    source_checksum = "sha256-value",
    source_path = "/source_docs/unclassified/ASML_XT-1060K.pdf",
    parser_version = "parser-v1",
    splitter_version = "splitter-v1",
    embedding_model = "BAAI/bge-base-zh-v1.5",
    embedding_dim = 768,
    expected_chunk_count = 100,
    persisted_chunk_count = 100,
    embedded_chunk_count = 100,
    status = "completed",
    dagster_run_id = "dagster-run-1",
    error_stage = json.null,
    error_message = json.null,
    created_at = "2026-08-04T10:00:00+08:00",
    completed_at = "2026-08-04T10:05:00+08:00",
    is_current = true,
  }
  local value = {
    request_id = "a7bb4493-0ad2-4e0c-b11d-0ff2dd4a3915",
    asset_id = "f440c18e-a281-44bc-a878-8aa92b620879",
    asset_key = "unclassified/ASML_XT-1060K.pdf",
    asset_name = "ASML_XT-1060K.pdf",
    current_version_id = version.version_id,
    current_version = version,
    raw_document = {
      raw_document_id = "a4bc7eb7-8061-41f7-9460-16ec667a0ee0",
      content_length = 123456,
      metadata = { loader = "pdf", page_count = 280 },
      created_at = "2026-08-04T10:01:00+08:00",
    },
    chunk_summary = {
      total_chunk_count = 100,
      embedded_chunk_count = 100,
      pending_chunk_count = 0,
      failed_chunk_count = 0,
      first_chunk_id = 1,
      last_chunk_id = 100,
    },
    versions = json.array({ version }),
    created_at = "2026-08-04T10:00:00+08:00",
    updated_at = "2026-08-04T10:05:00+08:00",
  }
  for key, item in pairs(overrides or {}) do value[key] = item end
  return value
end

function M.active_health_response(overrides)
  local value = {
    status = "ok",
    database = "ok",
    active_assets = 25,
    total_assets = 28,
    embedding_model = "BAAI/bge-base-zh-v1.5",
    embedding_dim = 768,
    graph_enabled = true,
  }
  for key, item in pairs(overrides or {}) do value[key] = item end
  return value
end

function M.graph_query_request(overrides)
  local value = {
    cypher = "MATCH (e) WHERE toLower(e.name) CONTAINS toLower($entity) RETURN e LIMIT $limit",
    parameters = { entity = "ASML", limit = 10 },
    limit = 10,
  }
  for key, item in pairs(overrides or {}) do value[key] = item end
  return value
end

function M.graph_query_response(overrides)
  local value = {
    request_id = "4a95f9c2-b8e7-4d1c-9d76-1ac79cbdcf8a",
    cypher = "MATCH (e) WHERE toLower(e.name) CONTAINS toLower($entity) RETURN e LIMIT $limit",
    parameters = { entity = "ASML", limit = 10 },
    limit = 10,
    elapsed_ms = 12.3,
    columns = json.array({ "e" }),
    row_count = 1,
    rows = json.array({
      {
        e = {
          element_id = "neo4j-element-id",
          labels = json.array({ "Equipment" }),
          properties = { name = "ASML XT-1060K" },
        },
      },
    }),
  }
  for key, item in pairs(overrides or {}) do value[key] = item end
  return value
end

function M.graph_health_response(overrides)
  local value = {
    status = "ok",
    database = "neo4j",
    uri = "bolt://neo4j.internal:7687",
  }
  for key, item in pairs(overrides or {}) do value[key] = item end
  return value
end

M.json = json
return M
