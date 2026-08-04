-- 把白名单和请求/响应 schemas 构造成决策器。
local UrlFilter = require("waf.url_filter")
local JsonValidator = require("waf.json_validator")
local Decision = require("waf.decision")
local PolicyEngine = require("waf.policy_engine")

local factory = {}

function factory.build_decision(config, opts, policies)
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
    policy_engine = PolicyEngine.new(policies or {}, opts),
  })
end

return factory
