describe("operations-managed WAF rules", function()
  local lint, config

  before_each(function()
    package.loaded["waf.rules_lint"] = nil
    lint = require("waf.rules_lint")
    config = require("spec.fixtures").config()
  end)

  it("loads and passes static lint", function()
    assert.are.equal(0, lint.count(lint.lint(config), "error"))
  end)

  it("ships an empty active whitelist without version or direction gates", function()
    local active = require("spec.fixtures").active_config()
    assert.are.equal(0, #active.whitelist)
    assert.is_nil(active.version)
    assert.is_nil(active.direction)
    assert.are.equal(0, lint.count(lint.lint(active), "error"))
  end)

  it("keeps two knowledge routes in a non-active request example", function()
    assert.are.equal(2, #config.whitelist)
    assert.are.equal("GET", config.whitelist[1].methods[1])
    assert.are.equal("/ai/knowledge/health", config.whitelist[1].path)
    assert.are.equal("POST", config.whitelist[2].methods[1])
    assert.are.equal("knowledge_search_request", config.whitelist[2].request_schema)
  end)

  it("contains request schemas only", function()
    assert.truthy(config.schemas.knowledge_search_request)
    assert.is_nil(config.schemas.knowledge_search_response)
    for _, rule in ipairs(config.whitelist) do assert.is_nil(rule.response_schemas) end
  end)

  it("keeps unknown request fields closed", function()
    local schema = config.schemas.knowledge_search_request
    assert.is_false(schema.additional_properties)
    assert.are.equal(4000, schema.properties.query.max_length)
    assert.are.equal(50, schema.properties.top_k.maximum)
  end)
end)
