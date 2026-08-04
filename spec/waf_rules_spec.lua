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

  it("ships all five documented knowledge routes for the confirmed host", function()
    local active = require("spec.fixtures").active_config()
    local expected = {
      ["POST /ai/knowledge/search"] = "knowledge_search_request",
      ["GET /ai/knowledge/assets/{uuid}"] = false,
      ["GET /ai/knowledge/health"] = false,
      ["POST /ai/knowledge/graph/query"] = "knowledge_graph_query_request",
      ["GET /ai/knowledge/graph/health"] = false,
    }
    assert.are.equal(5, #active.whitelist)
    for _, rule in ipairs(active.whitelist) do
      assert.are.equal("kb.pxsemic.tech", rule.host)
      local key = rule.methods[1] .. " " .. (rule.path or rule.path_template)
      assert.is_not_nil(expected[key])
      if expected[key] == false then
        assert.is_nil(rule.request_schema)
      else
        assert.are.equal(expected[key], rule.request_schema)
      end
      expected[key] = nil
    end
    assert.is_nil(next(expected))
    assert.is_nil(active.version)
    assert.is_nil(active.direction)
    assert.are.equal(131072, active.max_request_body_bytes)
    assert.are.equal(1048576, active.max_response_body_bytes)
    local issues = lint.lint(active)
    assert.are.equal(0, lint.count(issues, "error"))
    assert.are.equal(5, lint.count(issues, "warn"))
  end)

  it("allows each documented request and response and rejects route or contract drift", function()
    local fixtures = require("spec.fixtures")
    local active = require("spec.fixtures").active_config()
    local decision = require("waf.factory").build_decision(active, {
      null_value = fixtures.json.null,
      array_mt = fixtures.json.array_mt,
    })

    local search = {
      host = "kb.pxsemic.tech",
      method = "POST",
      path = "/ai/knowledge/search",
      headers = { ["content-type"] = "application/json" },
      body_present = true,
      body = fixtures.active_search_request(),
    }
    local allowed_search = decision:evaluate(search)
    assert.are.equal("allow", allowed_search.action)
    local search_response = fixtures.active_search_response()
    search_response.results[1].metadata.loader = {
      pages = fixtures.json.array({ 1, 2 }),
    }
    assert.are.equal("allow",
      decision:validate_response(allowed_search.rule, 200,
        search_response).action)
    search.body = { top_k = 5 }
    assert.are.equal("request_body", decision:evaluate(search).reason)
    search.body = { query = "q", include_graph = true }
    assert.are.equal("request_body", decision:evaluate(search).reason)
    search.body = fixtures.active_search_request()
    search.host = "kb-1.pxsemic.tech"
    assert.are.equal("not_in_whitelist", decision:evaluate(search).reason)

    local asset = {
      host = "kb.pxsemic.tech",
      method = "GET",
      path = "/ai/knowledge/assets/f440c18e-a281-44bc-a878-8aa92b620879",
      headers = {},
      body_present = false,
    }
    local allowed_asset = decision:evaluate(asset)
    assert.are.equal("allow", allowed_asset.action)
    assert.are.equal("allow",
      decision:validate_response(allowed_asset.rule, 200, fixtures.asset_response()).action)
    asset.path = "/ai/knowledge/assets/not-a-uuid"
    assert.are.equal("not_in_whitelist", decision:evaluate(asset).reason)
    asset.path = "/ai/knowledge/assets/f440c18e-a281-44bc-a878-8aa92b620879/extra"
    assert.are.equal("not_in_whitelist", decision:evaluate(asset).reason)

    local health = {
      host = "kb.pxsemic.tech", method = "GET", path = "/ai/knowledge/health",
      headers = {}, body_present = false,
    }
    local allowed_health = decision:evaluate(health)
    assert.are.equal("allow",
      decision:validate_response(allowed_health.rule, 200,
        fixtures.active_health_response()).action)

    local graph = {
      host = "kb.pxsemic.tech",
      method = "POST",
      path = "/ai/knowledge/graph/query",
      headers = { ["content-type"] = "application/json" },
      body_present = true,
      body = fixtures.graph_query_request(),
    }
    local allowed_graph = decision:evaluate(graph)
    assert.are.equal("allow", allowed_graph.action)
    assert.are.equal("allow",
      decision:validate_response(allowed_graph.rule, 200,
        fixtures.graph_query_response()).action)
    graph.body = { cypher = "   " }
    assert.are.equal("request_body", decision:evaluate(graph).reason)
    graph.body = fixtures.graph_query_request({ limit = 1001 })
    assert.are.equal("request_body", decision:evaluate(graph).reason)
    graph.body = fixtures.graph_query_request({ unknown = true })
    assert.are.equal("request_body", decision:evaluate(graph).reason)
    graph.body = { cypher = string.rep("中", 20000) }
    assert.are.equal("allow", decision:evaluate(graph).action)
    graph.body = { cypher = string.rep("中", 20001) }
    assert.are.equal("request_body", decision:evaluate(graph).reason)

    local graph_health = {
      host = "kb.pxsemic.tech", method = "GET", path = "/ai/knowledge/graph/health",
      headers = {}, body_present = false,
    }
    local allowed_graph_health = decision:evaluate(graph_health)
    assert.are.equal("allow", decision:validate_response(allowed_graph_health.rule, 200,
      fixtures.graph_health_response()).action)

    local changed = fixtures.graph_query_response({ unexpected = true })
    assert.are.equal("response_body",
      decision:validate_response(allowed_graph.rule, 200, changed).reason)
    assert.are.equal("response_status_not_allowed",
      decision:validate_response(allowed_asset.rule, 404, fixtures.asset_response()).reason)
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
