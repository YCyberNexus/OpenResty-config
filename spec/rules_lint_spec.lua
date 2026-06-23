describe("rules_lint", function()
  local lint

  before_each(function()
    package.loaded["waf.rules_lint"] = nil
    lint = require("waf.rules_lint")
  end)

  local function errors(issues)
    return lint.count(issues, "error")
  end

  local function has(issues, level, substr)
    for _, i in ipairs(issues) do
      if i.level == level and tostring(i.msg):find(substr, 1, true) then return true end
    end
    return false
  end

  local function valid_config()
    return {
      whitelist = {
        { methods = { "POST" }, path = "/v1/chat/completions", body = "chat" },
        { methods = { "GET" }, path = "/v1/models" },
      },
      blacklist = {
        { pattern = "^/admin" },
      },
      schemas = {
        chat = {
          models = { "gpt-4o" },
          max_messages = 50,
          max_content_length = 8000,
          max_total_length = 32000,
          allowed_roles = { "system", "user", "assistant" },
          allowed_fields = { "model", "messages" },
        },
      },
    }
  end

  it("passes a valid config with zero errors", function()
    assert.are.equal(0, errors(lint.lint(valid_config())))
  end)

  it("flags a whitelist body referencing a missing schema", function()
    local c = valid_config()
    c.whitelist[1].body = "nope"
    assert.is_true(has(lint.lint(c), "error", "nope"))
  end)

  it("flags a schema missing a numeric max_messages", function()
    local c = valid_config()
    c.schemas.chat.max_messages = nil
    assert.is_true(has(lint.lint(c), "error", "max_messages"))
  end)

  it("flags allowed_fields missing model", function()
    local c = valid_config()
    c.schemas.chat.allowed_fields = { "messages" }
    assert.is_true(has(lint.lint(c), "error", "model"))
  end)

  it("flags a whitelist rule with neither path nor pattern", function()
    local c = valid_config()
    c.whitelist[#c.whitelist + 1] = { methods = { "POST" } }
    assert.is_true(has(lint.lint(c), "error", "path"))
  end)

  it("flags an empty models list", function()
    local c = valid_config()
    c.schemas.chat.models = {}
    assert.is_true(has(lint.lint(c), "error", "models"))
  end)

  it("warns when a rule sets both path and pattern", function()
    local c = valid_config()
    c.whitelist[2].pattern = "^/v1/models$"
    assert.is_true(has(lint.lint(c), "warn", "pattern"))
  end)

  it("flags a blacklist rule with neither path nor pattern", function()
    local c = valid_config()
    c.blacklist[#c.blacklist + 1] = {}
    assert.is_true(has(lint.lint(c), "error", "path"))
  end)

  it("flags a non-positive max_messages", function()
    local c = valid_config()
    c.schemas.chat.max_messages = 0
    assert.is_true(has(lint.lint(c), "error", "max_messages"))
  end)

  it("flags allowed_fields missing entirely as a root cause", function()
    local c = valid_config()
    c.schemas.chat.allowed_fields = nil
    assert.is_true(has(lint.lint(c), "error", "allowed_fields"))
  end)

  it("flags a lowercase method (case-sensitive, never matches)", function()
    local c = valid_config()
    c.whitelist[1].methods = { "post" }
    assert.is_true(has(lint.lint(c), "error", "POST"))
  end)

  it("flags a blacklist methods that is not an array (would silently bypass)", function()
    local c = valid_config()
    c.blacklist[1].methods = "GET"
    assert.is_true(has(lint.lint(c), "error", "数组"))
  end)

  it("flags a body schema attached to a bodyless method (GET)", function()
    local c = valid_config()
    c.whitelist[2].body = "chat"
    assert.is_true(has(lint.lint(c), "error", "400"))
  end)

  it("flags a path present in both whitelist and blacklist", function()
    local c = valid_config()
    c.blacklist[#c.blacklist + 1] = { path = "/v1/models" }
    assert.is_true(has(lint.lint(c), "error", "/v1/models"))
  end)

  it("flags overlapping same-path rules with inconsistent body (bypass risk)", function()
    local c = valid_config()
    c.whitelist[#c.whitelist + 1] = { methods = { "POST" }, path = "/v1/chat/completions" }
    assert.is_true(has(lint.lint(c), "error", "/v1/chat/completions"))
  end)

  it("warns when allowed_roles omits user", function()
    local c = valid_config()
    c.schemas.chat.allowed_roles = { "system", "assistant" }
    assert.is_true(has(lint.lint(c), "warn", "user"))
  end)

  it("does not flag GET and POST sharing a path (different methods, no overlap)", function()
    local c = valid_config()
    -- /v1/models 已有 GET；再加同 path 的 POST+body，方法不重叠，不应误报短路
    c.whitelist[#c.whitelist + 1] = { methods = { "POST" }, path = "/v1/models", body = "chat" }
    local issues = lint.lint(c)
    local bypass = false
    for _, i in ipairs(issues) do
      if i.level == "error" and tostring(i.msg):find("短路", 1, true) then bypass = true end
    end
    assert.is_false(bypass)
  end)

  it("passes a config whose forbidden_headers are valid lowercase names", function()
    local c = valid_config()
    c.forbidden_headers = { "x-openclaw-model" }
    assert.are.equal(0, errors(lint.lint(c)))
  end)

  it("flags forbidden_headers that is not an array", function()
    local c = valid_config()
    c.forbidden_headers = "x-openclaw-model"
    assert.is_true(has(lint.lint(c), "error", "数组"))
  end)

  it("warns about an uppercase forbidden header name (style, runtime still normalizes)", function()
    local c = valid_config()
    c.forbidden_headers = { "X-OpenClaw-Model" }
    assert.is_true(has(lint.lint(c), "warn", "小写"))
  end)

  it("treats an uppercase forbidden header as warn, not error (runtime lowercases it)", function()
    local c = valid_config()
    c.forbidden_headers = { "X-OpenClaw-Model" }
    assert.are.equal(0, errors(lint.lint(c)))
  end)

  it("flags a non-string forbidden header element", function()
    local c = valid_config()
    c.forbidden_headers = { 123 }
    assert.is_true(has(lint.lint(c), "error", "字符串"))
  end)

  it("flags a bare \"*\" forbidden header (would block all requests)", function()
    local c = valid_config()
    c.forbidden_headers = { "*" }
    assert.is_true(has(lint.lint(c), "error", "拦死"))
  end)

  it("warns about a misplaced wildcard in a forbidden header name", function()
    local c = valid_config()
    c.forbidden_headers = { "x-*-model" }
    assert.is_true(has(lint.lint(c), "warn", "通配符"))
  end)
end)
