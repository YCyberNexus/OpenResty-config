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
      models = { "openclaw", "openclaw/default" },
      max_messages = 50,
      max_content_length = 8000,
      max_total_length = 32000,
      allowed_roles = { "system", "user", "assistant" },
      allowed_fields = { "model", "messages", "stream", "user", "temperature",
        "top_p", "frequency_penalty", "presence_penalty", "seed",
        "max_tokens", "max_completion_tokens", "stop" },
    })
    return Decision.new({
      whitelist = whitelist, blacklist = blacklist, validators = { chat = chat },
      forbidden_headers = { "x-openclaw-*" },
    })
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
    local r = build():evaluate({ method = "POST", path = "/v1/chat/completions", body = { model = "openclaw" } })
    assert.are.equal("deny", r.action)
    assert.are.equal("body", r.reason)
  end)

  it("allows a whitelisted request whose body passes validation", function()
    local r = build():evaluate({
      method = "POST",
      path = "/v1/chat/completions",
      body = { model = "openclaw", messages = { { role = "user", content = "hi" } } },
    })
    assert.are.equal("allow", r.action)
  end)

  it("denies a request carrying a forbidden header (x-openclaw-model)", function()
    local r = build():evaluate({
      method = "POST",
      path = "/v1/chat/completions",
      headers = { ["x-openclaw-model"] = "openclaw/secret" },
      body = { model = "openclaw", messages = { { role = "user", content = "hi" } } },
    })
    assert.are.equal("deny", r.action)
    assert.are.equal("forbidden_header", r.reason)
    assert.are.equal(403, r.status)
    assert.are.equal("x-openclaw-model", r.field)
  end)

  it("checks forbidden headers BEFORE the blacklist (order is load-bearing)", function()
    -- 既命中黑名单 path、又带禁用头：必须以 forbidden_header 拒,而不是 blacklist
    local r = build():evaluate({
      method = "POST",
      path = "/v1/admin",
      headers = { ["x-openclaw-model"] = "x" },
    })
    assert.are.equal("forbidden_header", r.reason)
    assert.are.equal(403, r.status)
  end)

  it("matches the whole x-openclaw-* family, not just x-openclaw-model", function()
    local r = build():evaluate({
      method = "POST",
      path = "/v1/chat/completions",
      headers = { ["x-openclaw-agent"] = "root" },
      body = { model = "openclaw", messages = { { role = "user", content = "hi" } } },
    })
    assert.are.equal("forbidden_header", r.reason)
  end)

  it("normalizes config case: an uppercase forbidden-header config still matches", function()
    local d = Decision.new({
      whitelist = UrlFilter.new({ { methods = { "POST" }, path = "/v1/x" } }),
      blacklist = UrlFilter.new({}),
      forbidden_headers = { "X-OpenClaw-Model" },   -- 大写配置,运行时应规范化后仍命中
    })
    local r = d:evaluate({ method = "POST", path = "/v1/x", headers = { ["x-openclaw-model"] = "v" } })
    assert.are.equal("forbidden_header", r.reason)
  end)

  it("normalizes underscore header form (x_openclaw_model) to the dashed family", function()
    local r = build():evaluate({
      method = "POST",
      path = "/v1/chat/completions",
      headers = { ["x_openclaw_model"] = "v" },
      body = { model = "openclaw", messages = { { role = "user", content = "hi" } } },
    })
    assert.are.equal("forbidden_header", r.reason)
  end)

  it("fail-closes (400 too_many_headers) when headers were truncated", function()
    local r = build():evaluate({
      method = "POST",
      path = "/v1/chat/completions",
      headers = {},                 -- 截断后表本身可能不含禁用头,但不可信
      headers_truncated = true,
      body = { model = "openclaw", messages = { { role = "user", content = "hi" } } },
    })
    assert.are.equal("deny", r.action)
    assert.are.equal("too_many_headers", r.reason)
    assert.are.equal(400, r.status)
  end)

  it("treats a bare \"*\" forbidden header as a no-op (does not block every request)", function()
    local d = Decision.new({
      whitelist = UrlFilter.new({ { methods = { "GET" }, path = "/v1/models" } }),
      blacklist = UrlFilter.new({}),
      forbidden_headers = { "*" },
    })
    local r = d:evaluate({ method = "GET", path = "/v1/models", headers = { ["accept"] = "x" } })
    assert.are.equal("allow", r.action)
  end)

  it("allows a request whose headers do not include any forbidden header", function()
    local r = build():evaluate({
      method = "POST",
      path = "/v1/chat/completions",
      headers = { ["content-type"] = "application/json" },
      body = { model = "openclaw", messages = { { role = "user", content = "hi" } } },
    })
    assert.are.equal("allow", r.action)
  end)
end)
