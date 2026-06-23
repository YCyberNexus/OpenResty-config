-- WAF 规则定义（OpenClaw OpenAI 兼容网关）。
-- 起步阶段用 Lua 表直接定义，OpenResty 原生加载、零依赖、可 diff。
-- 生产应迁移到 JSON/YAML + 配置中心 + 热更新（方案 P5：版本号 + lrucache + 加载前校验）。
--
-- 端点 / 字段 / model 形态依据 OpenClaw 官方文档 docs.openclaw.ai/gateway/openai-http-api：
--   官方暴露 5 个端点：POST /v1/chat/completions、GET /v1/models、GET /v1/models/{id}、
--   POST /v1/embeddings、POST /v1/responses；该网关默认关闭、按需在 OpenClaw config 启用。
-- 标 “TODO(部署确认)” 的项取决于你们这套 OpenClaw 实例实际怎么配，需向运维/应用方核实后据实收紧。
-- 标 “TODO(安全基线)” 的项文档未规定、属本网关自定的安全口径，按基线/容量拍板。
return {
  -- 白名单：未命中一律拒绝（默认拒绝 / fail-closed）。body 指向 schemas 里的校验器名。
  -- 最小授权：只放当前确需的端点；其余官方端点默认不开，确认在用再放（见下方注释）。
  whitelist = {
    { methods = { "POST" }, path = "/v1/chat/completions", body = "chat" },
    { methods = { "GET" },  path = "/v1/models" },

    -- TODO(部署确认)：以下端点 OpenClaw 支持但默认关闭，确认实例对外启用了再逐条放开：
    -- { methods = { "GET" },  pattern = [[^/v1/models/[^/]+$]] },              -- 单个模型详情（只读）
    -- { methods = { "POST" }, path = "/v1/embeddings", body = "embeddings" },  -- 需引擎侧新增 embeddings 校验器
    -- { methods = { "POST" }, path = "/v1/responses",  body = "responses" },   -- 需引擎侧新增 responses 校验器
  },

  -- 黑名单：先于白名单匹配，命中即拒。
  -- 该网关被官方定性为 operator-access（操作员级）面，从严拦控制面 / 管理端点。
  blacklist = {
    { pattern = "^/admin" },
    { pattern = "^/v1/admin" },
  },

  -- 禁用请求头：命中即 403（reason=forbidden_header），先于黑/白名单。头名全小写；末尾 * 为前缀匹配。
  -- OpenClaw 文档化的“后端 model 覆盖头”是 x-openclaw-model；该网关是 operator-access 面，
  -- 故按整族 x-openclaw-* 拦截（连未文档化/后续新增的同族覆盖头一并挡掉），防客户端旁路下方 model 白名单。
  -- 匹配对下划线形态（x_openclaw_model）等价处理；头条数超 get_headers 上限会被 fail-closed 拒（too_many_headers）。
  forbidden_headers = { "x-openclaw-*" },

  -- body 校验器（OpenAI Chat Completions 形态）。
  schemas = {
    chat = {
      -- TODO(部署确认)：OpenClaw 的 model id 形如 openclaw / openclaw/default / openclaw/<agentId>，
      -- 具体 agentId 取决于实例 models 配置。先放通用两个，向运维确认实际 agent 列表后补全。
      models = { "openclaw", "openclaw/default" },

      -- 未含 "tool" 角色——与下方刻意不放开 tools/function 调用保持一致（放开 tools 时再补 "tool"）。
      allowed_roles = { "system", "user", "assistant" },

      -- additionalProperties:false —— 只放官方文档列明、且本网关愿意接受的顶层字段。
      -- 已去掉占位里的 "n"（OpenClaw 文档未列）。tools/tool_choice 刻意不放（见下 TODO）。
      allowed_fields = {
        "model", "messages", "stream", "user",
        "temperature", "top_p", "frequency_penalty", "presence_penalty", "seed",
        "max_tokens", "max_completion_tokens", "stop",
      },
      -- TODO(安全基线)：tools / tool_choice（函数调用）会显著扩大攻击面，且当前校验器不深校 tools
      -- 结构。确需函数调用再把它们加进 allowed_fields，并同步补 tools 结构校验 + 放开 "tool" 角色。

      -- TODO(安全基线)：以下上限 OpenClaw 文档未规定，是本网关自定的安全口径，按基线/容量确认。
      -- 长度按字节计（#str），中文/emoji 偏大；后续补 utf8 双重口径（方案 P3-5）。
      max_messages = 50,
      max_content_length = 8000,
      max_total_length = 32000,
    },
  },
}
