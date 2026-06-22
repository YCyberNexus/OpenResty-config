-- WAF 规则定义（起步骨架）。
-- 起步阶段用 Lua 表直接定义，OpenResty 原生加载、零依赖、可 diff。
-- 生产应迁移到 JSON/YAML + 配置中心 + 热更新（方案 P5：版本号 + lrucache + 加载前校验）。
return {
  -- 白名单：未命中一律拒绝（默认拒绝）。body 字段指向 schemas 里的校验器名。
  whitelist = {
    { methods = { "POST" }, path = "/v1/chat/completions", body = "chat" },
    { methods = { "GET" },  path = "/v1/models" },
  },

  -- 黑名单：先于白名单匹配，命中即拒。
  -- 跨区一律拒绝 OpenClaw 控制面/管理端点（方案待澄清项 15、风险 25）。
  blacklist = {
    { pattern = "^/admin" },
    { pattern = "^/v1/admin" },
  },

  -- body 校验器（OpenAI Chat Completions 形态）。数值上限为占位，
  -- 待方案搁置项 5（接口契约）确认后据实收紧。
  schemas = {
    chat = {
      models = { "gpt-4o", "gpt-4o-mini", "claude-opus-4-8" },
      max_messages = 50,
      max_content_length = 8000,
      max_total_length = 32000,
      allowed_roles = { "system", "user", "assistant" },
      allowed_fields = { "model", "messages", "stream", "temperature", "top_p", "max_tokens", "n", "stop" },
    },
  },
}
