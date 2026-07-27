-- 运维维护的活动白名单配置。
--
-- 安装包默认不放行任何业务 URL；运维必须根据已审批台账逐条配置 whitelist、请求
-- schema 和响应 schema，并把同一版本同步到蓝、黄两侧 WAF。可参考同目录下的
-- waf_rules_knowledge_example.lua，但复制示例不等于获得生产放行授权。
return {
  version = "UNCONFIGURED-DENY-ALL",
  direction = "not_configured",
  example = false,

  max_request_body_bytes = 16384,
  max_response_body_bytes = 4194304,

  whitelist = {},

  -- 内部代理路径永远不作为业务入口。其它黑名单由运维按现场需求补充；即使黑名单
  -- 为空，未进入 whitelist 的 method+path 仍会默认拒绝。
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

  schemas = {},
}
