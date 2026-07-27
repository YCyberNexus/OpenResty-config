-- 运维规则示例：蓝区 -> 黄区知识库链路。
--
-- 本文件不会被生产 nginx 模板加载。运维只有在完成白名单、数据分级及接口审批后，
-- 才可据此生成 conf/waf_rules.lua，并将同一版本同步到蓝、黄两侧 WAF。
-- 来源：docs/知识库接口文档.md。文档未给出的限制均为示例保护值，需上线前确认。
return {
  version = "EXAMPLE-2026-07-26.knowledge-v1",
  direction = "blue_to_yellow",
  example = true,

  max_request_body_bytes = 16384,
  max_response_body_bytes = 4194304,

  whitelist = {
    {
      id = "BY-002-KNOWLEDGE-HEALTH",
      methods = { "GET" },
      path = "/ai/knowledge/health",
      response_schemas = {
        ["200"] = "knowledge_health_response",
      },
    },
    {
      id = "BY-002-KNOWLEDGE-SEARCH",
      methods = { "POST" },
      path = "/ai/knowledge/search",
      request_schema = "knowledge_search_request",
      response_schemas = {
        ["200"] = "knowledge_search_response",
        ["422"] = "knowledge_error_response",
        ["502"] = "knowledge_error_response",
        ["503"] = "knowledge_error_response",
      },
    },
  },

  blacklist = {
    { pattern = "^/_waf_" },
  },

  forbidden_headers = {
    "content-encoding",
    "x-http-method-override",
    "x-method-override",
    "x-original-url",
    "x-rewrite-url",
  },

  schemas = {
    knowledge_search_request = {
      type = "object",
      additional_properties = false,
      required = { "query" },
      properties = {
        query = {
          type = "string", min_length = 1, max_length = 4000,
          max_bytes = 16000, non_blank = true,
        },
        top_k = { type = "integer", minimum = 1, maximum = 50 },
      },
    },

    knowledge_health_response = {
      type = "object",
      additional_properties = false,
      required = {
        "status", "database", "active_assets", "total_assets",
        "embedding_model", "embedding_dim",
      },
      properties = {
        status = { type = "string", min_length = 1, max_length = 32 },
        database = { type = "string", min_length = 1, max_length = 32 },
        active_assets = { type = "integer", minimum = 0, maximum = 9007199254740991 },
        total_assets = { type = "integer", minimum = 0, maximum = 9007199254740991 },
        embedding_model = { type = "string", min_length = 1, max_length = 256 },
        embedding_dim = { type = "integer", minimum = 1, maximum = 65536 },
      },
    },

    knowledge_search_response = {
      type = "object",
      additional_properties = false,
      required = { "query", "top_k", "retrieval_mode", "embedding_model", "results" },
      properties = {
        query = {
          type = "string", min_length = 1, max_length = 4000,
          max_bytes = 16000, non_blank = true, trimmed = true,
        },
        top_k = { type = "integer", minimum = 1, maximum = 50 },
        retrieval_mode = {
          type = "string", enum = { "pgvector_active_versions_only" },
        },
        embedding_model = { type = "string", min_length = 1, max_length = 256 },
        results = {
          type = "array", max_items = 50,
          items = {
            type = "object",
            additional_properties = false,
            required = {
              "asset_id", "asset_key", "asset_name", "version_id", "version_no",
              "chunk_id", "chunk_index", "content", "page_number", "section_title",
              "metadata", "distance", "vector_score",
            },
            properties = {
              asset_id = { type = "string", format = "uuid" },
              asset_key = {
                type = "string", min_length = 1, max_length = 1024,
                max_bytes = 4096, format = "relative_path",
              },
              asset_name = {
                type = "string", min_length = 1, max_length = 512,
                max_bytes = 2048, format = "filename",
              },
              version_id = { type = "string", format = "uuid" },
              version_no = { type = "integer", minimum = 1, maximum = 9007199254740991 },
              chunk_id = { type = "integer", minimum = 0, maximum = 9007199254740991 },
              chunk_index = { type = "integer", minimum = 0, maximum = 9007199254740991 },
              content = {
                type = "string", min_length = 1, max_length = 32768,
                max_bytes = 131072,
              },
              page_number = {
                type = { "integer", "null" }, minimum = 1, maximum = 9007199254740991,
              },
              section_title = {
                type = { "string", "null" }, max_length = 1024, max_bytes = 4096,
              },
              metadata = {
                type = "object",
                additional_properties = false,
                properties = {
                  source = {
                    type = "string", min_length = 1, max_length = 2048,
                    max_bytes = 8192, format = "absolute_path", prefix = "/source_docs/",
                  },
                  page = { type = "integer", minimum = 0, maximum = 9007199254740991 },
                },
              },
              distance = { type = "number", minimum = 0, maximum = 2 },
              vector_score = { type = "number", minimum = -1, maximum = 1 },
            },
          },
        },
      },
    },

    knowledge_error_response = {
      type = "object",
      additional_properties = false,
      required = { "detail" },
      properties = {
        detail = { type = "string", min_length = 1, max_length = 1024, max_bytes = 4096 },
      },
    },
  },
}
