-- V2 可复用策略。规则只引用名称，新增普通接口无需修改 Lua 运行时。
return {
  version = 2,

  -- 三档超时由 Nginx 内部 location 固化；规则/路由只能从这里列出的名称中选择。
  timeout_profiles = {
    fast = true,
    standard = true,
    long = true,
  },

  -- 这些策略只做凭证存在性和语法门禁，真正的令牌/API Key 校验仍由目标服务完成。
  auth = {
    network_only = { mode = "none" },
    bearer = {
      mode = "bearer",
      header = "authorization",
      max_bytes = 4096,
    },
    api_key = {
      mode = "api_key",
      header = "x-api-key",
      max_bytes = 512,
    },
    basic = {
      mode = "basic",
      header = "authorization",
      max_bytes = 4096,
    },
  },

  -- 可审计的内置业务策略。只有规则显式引用时才会执行。
  request_policies = {
    cypher_read_only_v1 = {
      kind = "cypher_read_only",
      field = "cypher",
    },
  },
}
