-- 运维维护的活动白名单配置。
-- 安装包默认不放行任何业务 URL；按现场确认结果逐条填写 Host、method、path 及请求/响应 schema。
return {
  max_request_body_bytes = 16384,
  max_response_body_bytes = 1048576,

  whitelist = {},
  schemas = {},
}
