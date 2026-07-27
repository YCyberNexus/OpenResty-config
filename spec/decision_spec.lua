describe("decision", function()
  local factory, fixtures, decision

  before_each(function()
    package.loaded["waf.decision"] = nil
    package.loaded["waf.factory"] = nil
    factory = require("waf.factory")
    fixtures = require("spec.fixtures")
    decision = factory.build_decision(fixtures.config(), fixtures.regex_match, {
      null_value = fixtures.json.null,
      array_mt = fixtures.json.array_mt,
      allowed_hosts = { "blue-waf.internal" },
    })
  end)

  local function request(overrides)
    local value = {
      method = "POST",
      path = "/ai/knowledge/search",
      host = "blue-waf.internal",
      headers = { ["content-type"] = "application/json" },
      body = fixtures.search_request(),
      body_present = true,
    }
    for key, item in pairs(overrides or {}) do value[key] = item end
    return value
  end

  it("default-denies an unlisted method or path", function()
    assert.are.equal("not_in_whitelist", decision:evaluate(request({ path = "/ai/knowledge/export" })).reason)
    assert.are.equal("not_in_whitelist", decision:evaluate(request({ method = "PUT" })).reason)
  end)

  it("requires the deployment-specific Host allowlist", function()
    local result = decision:evaluate(request({ host = "attacker.example" }))
    assert.are.equal("deny", result.action)
    assert.are.equal("host_not_allowed", result.reason)
  end)

  it("rejects any query string on the registered URLs", function()
    local result = decision:evaluate(request({ args = "debug=true" }))
    assert.are.equal("query_not_allowed", result.reason)
  end)

  it("rejects a bare question mark with an empty query", function()
    local result = decision:evaluate(request({ args = "", query_present = true }))
    assert.are.equal("query_not_allowed", result.reason)
  end)

  it("rejects method/path override headers before URL evaluation", function()
    local result = decision:evaluate(request({
      path = "/not-listed",
      headers = { ["x-http-method-override"] = "GET" },
    }))
    assert.are.equal("forbidden_header", result.reason)
  end)

  it("rejects truncated headers fail-closed", function()
    local result = decision:evaluate(request({ headers_truncated = true }))
    assert.are.equal("too_many_headers", result.reason)
  end)

  it("rejects duplicate request headers", function()
    local result = decision:evaluate(request({
      headers = { ["content-type"] = { "application/json", "text/plain" } },
    }))
    assert.are.equal("duplicate_header", result.reason)
  end)

  it("rejects a body on the bodyless health URL", function()
    local result = decision:evaluate(request({
      method = "GET", path = "/ai/knowledge/health", body = nil,
    }))
    assert.are.equal("unexpected_body", result.reason)
  end)

  it("allows the documented search request", function()
    assert.are.equal("allow", decision:evaluate(request()).action)
  end)

  it("returns 400 for schema errors and 422 for policy limits", function()
    local schema_error = decision:evaluate(request({ body = { top_k = 5 } }))
    local policy_error = decision:evaluate(request({ body = { query = "q", top_k = 51 } }))
    assert.are.equal(400, schema_error.status)
    assert.are.equal(422, policy_error.status)
  end)

  it("accepts a response matching the configured status schema", function()
    local rule = decision:evaluate(request()).rule
    local result = decision:validate_response(rule, 200, fixtures.search_response(), fixtures.search_request())
    assert.are.equal("allow", result.action)
  end)

  it("rejects an upstream status that is not registered for the URL", function()
    local rule = decision:evaluate(request()).rule
    local result = decision:validate_response(rule, 500, { detail = "failure" }, fixtures.search_request())
    assert.are.equal("deny", result.action)
    assert.are.equal("response_status_not_allowed", result.reason)
    assert.are.equal(502, result.status)
  end)

  it("rejects a response that violates the configured response schema", function()
    local rule = decision:evaluate(request()).rule
    local response = fixtures.search_response({ top_k = "invalid" })
    local result = decision:validate_response(rule, 200, response, fixtures.search_request())
    assert.are.equal("deny", result.action)
    assert.are.equal("response_body", result.reason)
  end)
end)
