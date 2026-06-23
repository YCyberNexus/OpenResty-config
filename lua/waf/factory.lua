-- 装配工厂：把配置表（白名单 / 黑名单 / schemas）构造成一个 decision 决策器。
-- 纯逻辑，不依赖 ngx；regex_match 可选（生产注入基于 ngx.re 的 PCRE 实现）。
local UrlFilter = require("waf.url_filter")
local BodyValidator = require("waf.body_validator")
local Decision = require("waf.decision")

local factory = {}

function factory.build_decision(config, regex_match)
  config = config or {}
  local whitelist = UrlFilter.new(config.whitelist or {}, regex_match)
  local blacklist = UrlFilter.new(config.blacklist or {}, regex_match)
  local validators = {}
  for name, schema in pairs(config.schemas or {}) do
    validators[name] = BodyValidator.new(schema)
  end
  return Decision.new({
    whitelist = whitelist,
    blacklist = blacklist,
    validators = validators,
    forbidden_headers = config.forbidden_headers,
  })
end

return factory
