-- 请求白名单示例：蓝区 -> 黄区知识库链路。
-- 本文件只供本地测试，生产模板只加载 conf/waf_rules.lua。
return {
  max_request_body_bytes = 16384,

  whitelist = {
    {
      id = "BY-002-KNOWLEDGE-HEALTH",
      methods = { "GET" },
      path = "/ai/knowledge/health",
    },
    {
      id = "BY-002-KNOWLEDGE-SEARCH",
      methods = { "POST" },
      path = "/ai/knowledge/search",
      request_schema = "knowledge_search_request",
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
  },
}
