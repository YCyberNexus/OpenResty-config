-- 两个不同 Host 使用相同 method/path、不同请求和响应契约的最小示例。
-- 字段仅用于演示能力，不能替代两个真实服务的接口文档或生产审批。
return {
  max_request_body_bytes = 16384,
  max_response_body_bytes = 1048576,

  whitelist = {
    {
      id = "EXAMPLE-SERVICE-A-SEARCH",
      host = "service-a.example.internal",
      methods = { "POST" },
      path = "/ai/knowledge/search",
      request_schema = "service_a_request",
      responses = {
        [200] = { schema = "service_a_response", max_body_bytes = 65536 },
      },
    },
    {
      id = "EXAMPLE-SERVICE-B-SEARCH",
      host = "service-b.example.internal",
      methods = { "POST" },
      path = "/ai/knowledge/search",
      request_schema = "service_b_request",
      responses = {
        [200] = { schema = "service_b_response", max_body_bytes = 65536 },
      },
    },
  },

  schemas = {
    service_a_request = {
      type = "object",
      additional_properties = false,
      required = { "query" },
      properties = {
        query = { type = "string", min_length = 1, max_length = 1000, non_blank = true },
      },
    },
    service_a_response = {
      type = "object",
      additional_properties = false,
      required = { "results" },
      properties = {
        results = { type = "array", max_items = 20, items = { type = "string" } },
      },
    },
    service_b_request = {
      type = "object",
      additional_properties = false,
      required = { "keyword", "limit" },
      properties = {
        keyword = { type = "string", min_length = 1, max_length = 500, non_blank = true },
        limit = { type = "integer", minimum = 1, maximum = 100 },
      },
    },
    service_b_response = {
      type = "object",
      additional_properties = false,
      required = { "items", "count" },
      properties = {
        items = {
          type = "array",
          max_items = 100,
          items = {
            type = "object",
            additional_properties = false,
            required = { "id", "title" },
            properties = {
              id = { type = "integer", minimum = 1 },
              title = { type = "string", min_length = 1, max_length = 500 },
            },
          },
        },
        count = { type = "integer", minimum = 0, maximum = 100 },
      },
    },
  },
}
