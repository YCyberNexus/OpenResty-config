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
      method = "POST",
      path = "/ai/knowledge/search",
      headers = { ["content-type"] = "application/json" },
      body = fixtures.search_request(),
      body_present = true,
    }
    for key, item in pairs(overrides or {}) do value[key] = item end
    return value
  end

  it("default-denies an unlisted method or path", function()
    assert.are.equal("not_in_whitelist", decision:evaluate(request({ path = "/not-listed" })).reason)
    assert.are.equal("not_in_whitelist", decision:evaluate(request({ method = "PUT" })).reason)
  end)

  it("rejects query strings, including a bare question mark", function()
    assert.are.equal("query_not_allowed", decision:evaluate(request({ args = "debug=true" })).reason)
    assert.are.equal("query_not_allowed", decision:evaluate(request({ args = "", query_present = true })).reason)
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
end)
