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
    assert.are.equal(1048576, active.max_response_body_bytes)
    assert.are.equal(0, lint.count(lint.lint(active), "error"))
  end)

  it("keeps two knowledge routes in a non-active request example", function()
    assert.are.equal(2, #config.whitelist)
    assert.are.equal("GET", config.whitelist[1].methods[1])
    assert.are.equal("/ai/knowledge/health", config.whitelist[1].path)
    assert.are.equal("POST", config.whitelist[2].methods[1])
    assert.are.equal("knowledge_search_request", config.whitelist[2].request_schema)
    assert.are.equal("127.0.0.1", config.whitelist[1].host)
    assert.are.equal("127.0.0.1", config.whitelist[2].host)
  end)

  it("contains request and status-specific response schemas", function()
    assert.truthy(config.schemas.knowledge_search_request)
    assert.truthy(config.schemas.knowledge_health_response)
    assert.truthy(config.schemas.knowledge_search_response)
    assert.truthy(config.schemas.knowledge_error_response)
    assert.are.equal("knowledge_search_response", config.whitelist[2].responses[200].schema)
    assert.are.equal("knowledge_error_response", config.whitelist[2].responses[422].schema)
  end)

  it("keeps unknown request fields closed", function()
    local schema = config.schemas.knowledge_search_request
    assert.is_false(schema.additional_properties)
    assert.are.equal(4000, schema.properties.query.max_length)
    assert.are.equal(50, schema.properties.top_k.maximum)
  end)

  it("supports two hosts with the same method/path and different contracts", function()
    local same_path = require("spec.fixtures").same_path_config()
    assert.are.equal(same_path.whitelist[1].path, same_path.whitelist[2].path)
    assert.are.equal(same_path.whitelist[1].methods[1], same_path.whitelist[2].methods[1])
    assert.is_false(same_path.whitelist[1].host == same_path.whitelist[2].host)
    assert.is_false(same_path.whitelist[1].request_schema == same_path.whitelist[2].request_schema)
    assert.is_false(same_path.whitelist[1].responses[200].schema
      == same_path.whitelist[2].responses[200].schema)
  end)
end)
