describe("factory", function()
  local factory

  before_each(function()
    package.loaded["waf.factory"] = nil
    factory = require("waf.factory")
  end)

  local config = {
    whitelist = {
      { methods = { "POST" }, path = "/v1/chat/completions", body = "chat" },
    },
    blacklist = {
      { path = "/v1/admin" },
    },
    schemas = {
      chat = {
        models = { "openclaw", "openclaw/default" },
        max_messages = 50,
        max_content_length = 8000,
        max_total_length = 32000,
        allowed_roles = { "system", "user", "assistant" },
        allowed_fields = { "model", "messages" },
      },
    },
  }

  it("builds a decision that default-denies a non-whitelisted path", function()
    local d = factory.build_decision(config)
    assert.are.equal("deny", d:evaluate({ method = "POST", path = "/v1/unknown" }).action)
  end)

  it("builds a decision that denies a blacklisted path", function()
    local d = factory.build_decision(config)
    assert.are.equal("blacklist", d:evaluate({ method = "POST", path = "/v1/admin" }).reason)
  end)

  it("builds a decision that allows a valid chat request", function()
    local d = factory.build_decision(config)
    local r = d:evaluate({
      method = "POST",
      path = "/v1/chat/completions",
      body = { model = "openclaw", messages = { { role = "user", content = "hi" } } },
    })
    assert.are.equal("allow", r.action)
  end)

  it("builds a decision that rejects an invalid chat body", function()
    local d = factory.build_decision(config)
    local r = d:evaluate({ method = "POST", path = "/v1/chat/completions", body = { model = "evil" } })
    assert.are.equal("deny", r.action)
    assert.are.equal("body", r.reason)
  end)
end)
