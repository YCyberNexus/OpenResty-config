describe("factory", function()
  it("builds a request validator from the rules file", function()
    local fixtures = require("spec.fixtures")
    local decision = require("waf.factory").build_decision(fixtures.config(), {
      null_value = fixtures.json.null,
      array_mt = fixtures.json.array_mt,
    }, fixtures.policies())
    local result = decision:evaluate({
      host = "127.0.0.1",
      method = "POST",
      path = "/ai/knowledge/search",
      body_present = true,
      body = fixtures.search_request(),
      headers = {},
    })
    assert.are.equal("allow", result.action)
  end)
end)
