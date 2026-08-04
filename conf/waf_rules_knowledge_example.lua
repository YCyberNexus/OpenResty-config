-- 单服务知识库示例：用于本地 Host/请求/响应校验测试，不代表生产放行。
return {
  version = 2,
  limits = {
    max_query_string_bytes = 8192,
    max_buffered_request_body_bytes = 1048576,
    max_buffered_response_body_bytes = 1048576,
    max_stream_request_body_bytes = 67108864,
    max_stream_response_body_bytes = 268435456,
  },

  whitelist = {
    {
      id = "BY-002-KNOWLEDGE-HEALTH",
      host = "127.0.0.1",
      methods = { "GET" },
      path = "/ai/knowledge/health",
      transport = "buffered",
      auth_policy = "network_only",
      responses = {
        [200] = { body = { mode = "json", media_types = { "application/json" },
          schema = "knowledge_health_response", max_body_bytes = 16384 } },
      },
    },
    {
      id = "BY-002-KNOWLEDGE-SEARCH",
      host = "127.0.0.1",
      methods = { "POST" },
      path = "/ai/knowledge/search",
      transport = "buffered",
      auth_policy = "network_only",
      request = {
        body = { mode = "json", required = true, media_types = { "application/json" },
          schema = "knowledge_search_request", max_body_bytes = 16384, audit_body = true },
      },
      responses = {
        [200] = { body = { mode = "json", media_types = { "application/json" },
          schema = "knowledge_search_response", max_body_bytes = 1048576, audit_body = true } },
        [422] = { body = { mode = "json", media_types = { "application/json" },
          schema = "knowledge_error_response", max_body_bytes = 16384 } },
        [502] = { body = { mode = "json", media_types = { "application/json" },
          schema = "knowledge_error_response", max_body_bytes = 16384 } },
        [503] = { body = { mode = "json", media_types = { "application/json" },
          schema = "knowledge_error_response", max_body_bytes = 16384 } },
      },
    },
  },

  schemas = {
    knowledge_search_request = {
      type = "object",
      additional_properties = false,
      required = { "query" },
      properties = {
        query = {
          type = "string",
          min_length = 1,
          max_length = 4000,
          max_bytes = 16000,
          non_blank = true,
        },
        top_k = { type = "integer", minimum = 1, maximum = 50 },
      },
    },
    knowledge_health_response = {
      type = "object",
      additional_properties = false,
      required = {
        "status", "database", "active_assets", "total_assets", "embedding_model", "embedding_dim",
      },
      properties = {
        status = { type = "string", min_length = 1, max_length = 32 },
        database = { type = "string", min_length = 1, max_length = 32 },
        active_assets = { type = "integer", minimum = 0 },
        total_assets = { type = "integer", minimum = 0 },
        embedding_model = { type = "string", min_length = 1, max_length = 256 },
        embedding_dim = { type = "integer", minimum = 1 },
      },
    },
    knowledge_search_response = {
      type = "object",
      additional_properties = false,
      required = { "query", "top_k", "retrieval_mode", "embedding_model", "results" },
      properties = {
        query = { type = "string", min_length = 1, max_length = 4000, max_bytes = 16000 },
        top_k = { type = "integer", minimum = 1, maximum = 50 },
        retrieval_mode = { type = "string", enum = { "pgvector_active_versions_only" } },
        embedding_model = { type = "string", min_length = 1, max_length = 256 },
        results = {
          type = "array",
          max_items = 50,
          items = {
            type = "object",
            additional_properties = false,
            required = {
              "asset_id", "asset_key", "asset_name", "version_id", "version_no", "chunk_id",
              "chunk_index", "content", "page_number", "section_title", "metadata", "distance",
              "vector_score",
            },
            properties = {
              asset_id = { type = "string", format = "uuid" },
              asset_key = { type = "string", format = "relative_path" },
              asset_name = { type = "string", format = "filename" },
              version_id = { type = "string", format = "uuid" },
              version_no = { type = "integer", minimum = 1 },
              chunk_id = { type = "integer", minimum = 1 },
              chunk_index = { type = "integer", minimum = 0 },
              content = { type = "string" },
              page_number = { type = { "integer", "null" }, minimum = 1 },
              section_title = { type = { "string", "null" }, max_length = 1000 },
              metadata = {
                type = "object",
                additional_properties = false,
                properties = {
                  source = { type = "string", format = "absolute_path" },
                  page = { type = "integer", minimum = 0 },
                },
              },
              distance = { type = "number" },
              vector_score = { type = "number" },
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
        detail = { type = "string", min_length = 1, max_length = 1000 },
      },
    },
  },
}
