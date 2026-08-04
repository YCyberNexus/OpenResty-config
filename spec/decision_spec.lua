describe("decision", function()
  local factory, fixtures, decision

  before_each(function()
    package.loaded["waf.decision"] = nil
    package.loaded["waf.factory"] = nil
    factory = require("waf.factory")
    fixtures = require("spec.fixtures")
    decision = factory.build_decision(fixtures.config(), {
      null_value = fixtures.json.null,
      array_mt = fixtures.json.array_mt,
    })
  end)

  local function request(overrides)
    local value = {
      host = "127.0.0.1",
      method = "POST",
      path = "/ai/knowledge/search",
      headers = { ["content-type"] = "application/json" },
      body = fixtures.search_request(),
      body_present = true,
    }
    for key, item in pairs(overrides or {}) do value[key] = item end
    return value
  end

  it("default-denies an unlisted host, method, or path", function()
    assert.are.equal("not_in_whitelist",
      decision:evaluate(request({ host = "other.example.internal" })).reason)
    assert.are.equal("not_in_whitelist", decision:evaluate(request({ path = "/not-listed" })).reason)
    assert.are.equal("not_in_whitelist", decision:evaluate(request({ method = "PUT" })).reason)
  end)

  it("rejects query strings, including a bare question mark", function()
    assert.are.equal("query_not_allowed", decision:evaluate(request({ args = "debug=true" })).reason)
    assert.are.equal("query_not_allowed", decision:evaluate(request({ args = "", query_present = true })).reason)
  end)

  it("rejects a raw path that Nginx normalized into an allowed path", function()
    local result = decision:evaluate(request({
      path = "/ai/knowledge/search",
      raw_path = "/ai//knowledge/search",
    }))
    assert.are.equal("non_canonical_path", result.reason)
  end)

  it("rejects truncated and duplicate headers", function()
    assert.are.equal("too_many_headers", decision:evaluate(request({ headers_truncated = true })).reason)
    local duplicate = decision:evaluate(request({
      headers = { ["content-type"] = { "application/json", "text/plain" } },
    }))
    assert.are.equal("duplicate_header", duplicate.reason)
  end)

  it("ignores method-override headers because Nginx does not forward client headers", function()
    local result = decision:evaluate(request({ headers = { ["x-http-method-override"] = "GET" } }))
    assert.are.equal("allow", result.action)
  end)

  it("rejects a body on a bodyless whitelist rule", function()
    local result = decision:evaluate(request({ method = "GET", path = "/ai/knowledge/health" }))
    assert.are.equal("unexpected_body", result.reason)
  end)

  it("allows the documented search request", function()
    assert.are.equal("allow", decision:evaluate(request()).action)
  end)

  it("returns 400 for schema errors and 422 for configured policy limits", function()
    local schema_error = decision:evaluate(request({ body = { top_k = 5 } }))
    local policy_error = decision:evaluate(request({ body = { query = "q", top_k = 51 } }))
    assert.are.equal(400, schema_error.status)
    assert.are.equal(422, policy_error.status)
  end)

  it("validates an allowed response by status and schema", function()
    local rule = decision:match(request()).rule
    assert.are.equal("allow",
      decision:validate_response(rule, 200, fixtures.search_response()).action)
    assert.are.equal("response_body",
      decision:validate_response(rule, 200, { query = "missing fields" }).reason)
    assert.are.equal("response_status_not_allowed",
      decision:validate_response(rule, 201, fixtures.search_response()).reason)
  end)

  it("uses different request and response schemas for the same path on different hosts", function()
    local isolated = factory.build_decision(fixtures.same_path_config(), {
      null_value = fixtures.json.null,
      array_mt = fixtures.json.array_mt,
    })
    local a = {
      host = "service-a.example.internal", method = "POST", path = "/ai/knowledge/search",
      body_present = true, headers = {}, body = { query = "q" },
    }
    local b = {
      host = "service-b.example.internal", method = "POST", path = "/ai/knowledge/search",
      body_present = true, headers = {}, body = { keyword = "k", limit = 2 },
    }
    assert.are.equal("allow", isolated:evaluate(a).action)
    assert.are.equal("allow", isolated:evaluate(b).action)
    a.body = b.body
    b.body = { query = "q" }
    assert.are.equal("request_body", isolated:evaluate(a).reason)
    assert.are.equal("request_body", isolated:evaluate(b).reason)

    local rule_a = isolated:match(a).rule
    local rule_b = isolated:match(b).rule
    local response_a = { results = fixtures.json.array({ "one" }) }
    local response_b = {
      items = fixtures.json.array({ { id = 1, title = "one" } }), count = 1,
    }
    assert.are.equal("allow", isolated:validate_response(rule_a, 200, response_a).action)
    assert.are.equal("allow", isolated:validate_response(rule_b, 200, response_b).action)
    assert.are.equal("response_body", isolated:validate_response(rule_a, 200, response_b).reason)
    assert.are.equal("response_body", isolated:validate_response(rule_b, 200, response_a).reason)
  end)
end)
