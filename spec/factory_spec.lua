describe("factory", function()
  local factory, fixtures, decision

  before_each(function()
    package.loaded["waf.factory"] = nil
    factory = require("waf.factory")
    fixtures = require("spec.fixtures")
    decision = factory.build_decision(fixtures.config(), fixtures.regex_match, {
      null_value = fixtures.json.null,
      array_mt = fixtures.json.array_mt,
      allowed_hosts = { "localhost" },
    })
  end)

  it("builds request and response validators from an injected operations config", function()
    local request = {
      method = "POST", path = "/ai/knowledge/search", host = "localhost",
      body_present = true, body = fixtures.search_request(), headers = {},
    }
    local allowed = decision:evaluate(request)
    assert.are.equal("allow", allowed.action)
    assert.are.equal("allow", decision:validate_response(
      allowed.rule, 200, fixtures.search_response(), request.body
    ).action)
  end)

  it("fails closed when no allowed_hosts runtime setting is supplied", function()
    local without_hosts = factory.build_decision(fixtures.config(), fixtures.regex_match, {
      null_value = fixtures.json.null,
      array_mt = fixtures.json.array_mt,
    })
    local result = without_hosts:evaluate({
      method = "GET", path = "/ai/knowledge/health", host = "localhost", headers = {},
    })
    assert.are.equal("misconfigured", result.reason)
  end)
end)
