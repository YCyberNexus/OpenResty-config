describe("decision", function()
  local Decision, UrlFilter, BodyValidator

  before_each(function()
    package.loaded["waf.decision"] = nil
    Decision = require("waf.decision")
    UrlFilter = require("waf.url_filter")
    BodyValidator = require("waf.body_validator")
  end)

  -- 组装一个真实的决策器：白名单 + 黑名单 + 一个 chat body 校验器
  local function build()
    local whitelist = UrlFilter.new({
      { methods = { "POST" }, path = "/v1/chat/completions", body = "chat" },
      { methods = { "GET" }, path = "/v1/models" },
    })
    local blacklist = UrlFilter.new({
      { path = "/v1/admin" },
    })
    local chat = BodyValidator.new({
      models = { "gpt-4o" },
      max_messages = 50,
      max_content_length = 8000,
      max_total_length = 32000,
      allowed_roles = { "system", "user", "assistant" },
      allowed_fields = { "model", "messages", "stream", "temperature", "top_p", "max_tokens", "n", "stop" },
    })
    return Decision.new({ whitelist = whitelist, blacklist = blacklist, validators = { chat = chat } })
  end

  it("denies a request that matches the blacklist before checking the whitelist", function()
    local r = build():evaluate({ method = "POST", path = "/v1/admin" })
    assert.are.equal("deny", r.action)
    assert.are.equal("blacklist", r.reason)
    assert.are.equal(403, r.status)
  end)

  it("denies a request that is not in the whitelist (default deny)", function()
    local r = build():evaluate({ method = "POST", path = "/v1/unknown" })
    assert.are.equal("deny", r.action)
    assert.are.equal("not_in_whitelist", r.reason)
    assert.are.equal(403, r.status)
  end)

  it("allows a whitelisted request that needs no body schema", function()
    local r = build():evaluate({ method = "GET", path = "/v1/models" })
    assert.are.equal("allow", r.action)
  end)

  it("denies a whitelisted request whose body fails validation", function()
    local r = build():evaluate({ method = "POST", path = "/v1/chat/completions", body = { model = "gpt-4o" } })
    assert.are.equal("deny", r.action)
    assert.are.equal("body", r.reason)
  end)

  it("allows a whitelisted request whose body passes validation", function()
    local r = build():evaluate({
      method = "POST",
      path = "/v1/chat/completions",
      body = { model = "gpt-4o", messages = { { role = "user", content = "hi" } } },
    })
    assert.are.equal("allow", r.action)
  end)
end)
