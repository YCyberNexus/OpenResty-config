-- 运维维护的活动白名单配置。
-- BY-002：蓝 WAF -> 黄 WAF -> 黄区知识库，只放行已登记的五个知识库 API。

local arbitrary_object = {
  type = "object",
  -- 接口契约明确 parameters、metadata 和图谱行是动态对象；静态体检会保留偏离告警。
  additional_properties = true,
  properties = {},
}

local nullable_uuid = { type = { "string", "null" }, format = "uuid" }
local nullable_string = { type = { "string", "null" } }

local version_summary = {
  type = "object",
  additional_properties = false,
  required = {
    "version_id", "version_no", "source_checksum", "source_path", "parser_version",
    "splitter_version", "embedding_model", "embedding_dim", "expected_chunk_count",
    "persisted_chunk_count", "embedded_chunk_count", "status", "dagster_run_id",
    "error_stage", "error_message", "created_at", "completed_at", "is_current",
  },
  properties = {
    version_id = { type = "string", format = "uuid" },
    version_no = { type = "integer", minimum = 1 },
    source_checksum = { type = "string", min_length = 1 },
    source_path = { type = "string" },
    parser_version = { type = "string" },
    splitter_version = { type = "string" },
    embedding_model = { type = "string" },
    embedding_dim = { type = "integer", minimum = 1 },
    expected_chunk_count = { type = { "integer", "null" }, minimum = 0 },
    persisted_chunk_count = { type = "integer", minimum = 0 },
    embedded_chunk_count = { type = "integer", minimum = 0 },
    status = { type = "string", min_length = 1 },
    dagster_run_id = nullable_string,
    error_stage = nullable_string,
    error_message = nullable_string,
    created_at = { type = "string", min_length = 1 },
    completed_at = nullable_string,
    is_current = { type = "boolean" },
  },
}

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
      id = "BY-002-KB-SEARCH",
      host = "kb.pxsemic.tech",
      methods = { "POST" },
      path = "/ai/knowledge/search",
      transport = "buffered",
      auth_policy = "network_only",
      request = {
        body = {
          mode = "json",
          required = true,
          media_types = { "application/json" },
          schema = "knowledge_search_request",
          max_body_bytes = 131072,
        },
      },
      responses = {
        [200] = { body = { mode = "json", media_types = { "application/json" },
          schema = "knowledge_search_response", max_body_bytes = 1048576 } },
        [422] = { body = { mode = "json", media_types = { "application/json" },
          schema = "knowledge_error_response", max_body_bytes = 16384 } },
        [502] = { body = { mode = "json", media_types = { "application/json" },
          schema = "knowledge_error_response", max_body_bytes = 16384 } },
        [503] = { body = { mode = "json", media_types = { "application/json" },
          schema = "knowledge_error_response", max_body_bytes = 16384 } },
      },
    },
    {
      id = "BY-002-KB-ASSET",
      host = "kb.pxsemic.tech",
      methods = { "GET" },
      path_template = "/ai/knowledge/assets/{asset_id}",
      path_parameters = {
        asset_id = { type = "string", format = "uuid" },
      },
      transport = "buffered",
      auth_policy = "network_only",
      responses = {
        [200] = { body = { mode = "json", media_types = { "application/json" },
          schema = "knowledge_asset_response", max_body_bytes = 1048576 } },
      },
    },
    {
      id = "BY-002-KB-HEALTH",
      host = "kb.pxsemic.tech",
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
      id = "BY-002-KB-GRAPH-QUERY",
      host = "kb.pxsemic.tech",
      methods = { "POST" },
      path = "/ai/knowledge/graph/query",
      transport = "buffered",
      auth_policy = "network_only",
      request = {
        policies = { "cypher_read_only_v1" },
        body = {
          mode = "json",
          required = true,
          media_types = { "application/json" },
          schema = "knowledge_graph_query_request",
          max_body_bytes = 131072,
        },
      },
      responses = {
        [200] = { body = { mode = "json", media_types = { "application/json" },
          schema = "knowledge_graph_query_response", max_body_bytes = 1048576 } },
      },
    },
    {
      id = "BY-002-KB-GRAPH-HEALTH",
      host = "kb.pxsemic.tech",
      methods = { "GET" },
      path = "/ai/knowledge/graph/health",
      transport = "buffered",
      auth_policy = "network_only",
      responses = {
        [200] = { body = { mode = "json", media_types = { "application/json" },
          schema = "knowledge_graph_health_response", max_body_bytes = 16384 } },
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

    knowledge_search_response = {
      type = "object",
      additional_properties = false,
      required = { "query", "top_k", "retrieval_mode", "embedding_model", "results" },
      properties = {
        query = { type = "string", min_length = 1, max_length = 4000, max_bytes = 16000 },
        top_k = { type = "integer", minimum = 1, maximum = 50 },
        retrieval_mode = { type = "string", enum = { "pgvector_active_versions_only" } },
        embedding_model = { type = "string", min_length = 1 },
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
              section_title = { type = { "string", "null" } },
              metadata = arbitrary_object,
              distance = { type = "number" },
              vector_score = { type = "number" },
            },
          },
        },
      },
    },

    knowledge_asset_response = {
      type = "object",
      additional_properties = false,
      required = {
        "request_id", "asset_id", "asset_key", "asset_name", "current_version_id",
        "current_version", "raw_document", "chunk_summary", "versions", "created_at",
        "updated_at",
      },
      properties = {
        request_id = { type = "string", format = "uuid" },
        asset_id = { type = "string", format = "uuid" },
        asset_key = { type = "string", format = "relative_path" },
        asset_name = { type = "string", format = "filename" },
        current_version_id = nullable_uuid,
        current_version = {
          type = { "object", "null" },
          additional_properties = false,
          required = version_summary.required,
          properties = version_summary.properties,
        },
        raw_document = {
          type = { "object", "null" },
          additional_properties = false,
          required = { "raw_document_id", "content_length", "metadata", "created_at" },
          properties = {
            raw_document_id = { type = "string", format = "uuid" },
            content_length = { type = "integer", minimum = 0 },
            metadata = arbitrary_object,
            created_at = { type = "string", min_length = 1 },
          },
        },
        chunk_summary = {
          type = { "object", "null" },
          additional_properties = false,
          required = {
            "total_chunk_count", "embedded_chunk_count", "pending_chunk_count",
            "failed_chunk_count", "first_chunk_id", "last_chunk_id",
          },
          properties = {
            total_chunk_count = { type = "integer", minimum = 0 },
            embedded_chunk_count = { type = "integer", minimum = 0 },
            pending_chunk_count = { type = "integer", minimum = 0 },
            failed_chunk_count = { type = "integer", minimum = 0 },
            first_chunk_id = { type = { "integer", "null" }, minimum = 1 },
            last_chunk_id = { type = { "integer", "null" }, minimum = 1 },
          },
        },
        versions = { type = "array", items = version_summary },
        created_at = { type = "string", min_length = 1 },
        updated_at = { type = "string", min_length = 1 },
      },
    },

    knowledge_health_response = {
      type = "object",
      additional_properties = false,
      required = {
        "status", "database", "active_assets", "total_assets", "embedding_model",
        "embedding_dim", "graph_enabled",
      },
      properties = {
        status = { type = "string", min_length = 1 },
        database = { type = "string", min_length = 1 },
        active_assets = { type = "integer", minimum = 0 },
        total_assets = { type = "integer", minimum = 0 },
        embedding_model = nullable_string,
        embedding_dim = { type = "integer", minimum = 1 },
        graph_enabled = { type = "boolean" },
      },
    },

    knowledge_graph_query_request = {
      type = "object",
      additional_properties = false,
      required = { "cypher" },
      properties = {
        cypher = {
          type = "string",
          min_length = 1,
          max_length = 20000,
          max_bytes = 80000,
          non_blank = true,
        },
        parameters = arbitrary_object,
        limit = { type = "integer", minimum = 1, maximum = 1000 },
      },
    },

    knowledge_graph_query_response = {
      type = "object",
      additional_properties = false,
      required = {
        "request_id", "cypher", "parameters", "limit", "elapsed_ms", "columns",
        "row_count", "rows",
      },
      properties = {
        request_id = { type = "string", format = "uuid" },
        cypher = { type = "string", min_length = 1, max_length = 20000, max_bytes = 80000 },
        parameters = arbitrary_object,
        limit = { type = "integer", minimum = 1, maximum = 1000 },
        elapsed_ms = { type = "number", minimum = 0 },
        columns = {
          type = "array",
          items = { type = "string", min_length = 1 },
        },
        row_count = { type = "integer", minimum = 0, maximum = 1000 },
        rows = {
          type = "array",
          max_items = 1000,
          items = arbitrary_object,
        },
      },
    },

    knowledge_graph_health_response = {
      type = "object",
      additional_properties = false,
      required = { "status", "database", "uri" },
      properties = {
        status = { type = "string", min_length = 1 },
        database = { type = "string", enum = { "neo4j" } },
        uri = nullable_string,
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
