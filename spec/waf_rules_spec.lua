describe("operations-managed WAF rules", function()
  local lint, config

  before_each(function()
    package.loaded["waf.rules_lint"] = nil
    lint = require("waf.rules_lint")
    config = require("spec.fixtures").config()
  end)

  it("loads and passes static lint", function()
    local issues = lint.lint(config)
    assert.are.equal(0, lint.count(issues, "error"))
  end)

  it("ships the active configuration deny-all with no business URL", function()
    local active = require("spec.fixtures").active_config()
    assert.are.equal(0, #active.whitelist)
    assert.are.equal("UNCONFIGURED-DENY-ALL", active.version)
    local issues = lint.lint(active)
    assert.are.equal(0, lint.count(issues, "error"))
    assert.are.equal(1, lint.count(issues, "warn"))
  end)

  it("keeps the supplied knowledge routes in a non-active operations example", function()
    assert.are.equal("blue_to_yellow", config.direction)
    assert.are.equal(2, #config.whitelist)
    assert.are.equal("GET", config.whitelist[1].methods[1])
    assert.are.equal("/ai/knowledge/health", config.whitelist[1].path)
    assert.are.equal("POST", config.whitelist[2].methods[1])
    assert.are.equal("/ai/knowledge/search", config.whitelist[2].path)
  end)

  it("binds every URL to explicit response status schemas", function()
    for _, rule in ipairs(config.whitelist) do
      assert.truthy(rule.id)
      assert.truthy(rule.response_schemas and next(rule.response_schemas))
      assert.is_nil(rule.allow_query)
    end
  end)

  it("keeps the search request additional-properties closed", function()
    local schema = config.schemas.knowledge_search_request
    assert.is_false(schema.additional_properties)
    assert.are.equal(4000, schema.properties.query.max_length)
    assert.are.equal(50, schema.properties.top_k.maximum)
  end)

  it("keeps every response object additional-properties closed", function()
    assert.is_false(config.schemas.knowledge_health_response.additional_properties)
    assert.is_false(config.schemas.knowledge_search_response.additional_properties)
    assert.is_false(config.schemas.knowledge_error_response.additional_properties)
    assert.is_false(config.schemas.knowledge_search_response.properties.results.items.additional_properties)
  end)

  it("does not allow compressed or method-overridden requests", function()
    local found = {}
    for _, header in ipairs(config.forbidden_headers) do found[header] = true end
    assert.is_true(found["content-encoding"])
    assert.is_true(found["x-http-method-override"])
    assert.is_true(found["x-original-url"])
  end)
end)
