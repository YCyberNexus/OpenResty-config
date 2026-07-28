-- 运维维护的活动白名单配置。
-- 安装包默认不放行任何业务 URL；按现场确认结果逐条填写 method、path 和请求 schema。
return {
  max_request_body_bytes = 16384,

  whitelist = {},
  schemas = {},
}
