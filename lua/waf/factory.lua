-- 把白名单和请求 schemas 构造成请求决策器。
local UrlFilter = require("waf.url_filter")
local JsonValidator = require("waf.json_validator")
local Decision = require("waf.decision")

local factory = {}

function factory.build_decision(config, opts)
  config = config or {}
  opts = opts or {}
  local validators = {}
  for name, schema in pairs(config.schemas or {}) do
    validators[name] = JsonValidator.new(schema, {
      null_value = opts.null_value,
      array_mt = opts.array_mt,
    })
  end
  return Decision.new({
    whitelist = UrlFilter.new(config.whitelist or {}),
    validators = validators,
  })
end

return factory
