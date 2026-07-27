-- 装配工厂：把配置表（白名单 / 黑名单 / schemas）构造成一个 decision 决策器。
-- 纯逻辑，不依赖 ngx；运行时能力（正则、cjson null/array 标记）由调用方注入。
local UrlFilter = require("waf.url_filter")
local JsonValidator = require("waf.json_validator")
local Decision = require("waf.decision")

local factory = {}

function factory.build_decision(config, regex_match, opts)
  config = config or {}
  opts = opts or {}
  local whitelist = UrlFilter.new(config.whitelist or {}, regex_match)
  local blacklist = UrlFilter.new(config.blacklist or {}, regex_match)
  local validators = {}
  for name, schema in pairs(config.schemas or {}) do
    validators[name] = JsonValidator.new(schema, {
      null_value = opts.null_value,
      array_mt = opts.array_mt,
    })
  end
  return Decision.new({
    whitelist = whitelist,
    blacklist = blacklist,
    validators = validators,
    forbidden_headers = config.forbidden_headers,
    allowed_hosts = opts.allowed_hosts,
  })
end

return factory
