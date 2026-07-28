describe("rules_lint", function()
  local lint, fixtures

  before_each(function()
    package.loaded["waf.rules_lint"] = nil
    lint = require("waf.rules_lint")
    fixtures = require("spec.fixtures")
  end)

  local function has(issues, level, text)
    for _, issue in ipairs(issues) do
      if issue.level == level and (tostring(issue.where):find(text, 1, true)
        or tostring(issue.msg):find(text, 1, true)) then return true end
    end
    return false
  end

  it("passes the request-filtering example with zero issues", function()
    local issues = lint.lint(fixtures.config())
    assert.are.equal(0, lint.count(issues, "error"))
    assert.are.equal(0, lint.count(issues, "warn"))
  end)

  it("allows an empty deny-all rule file with one warning", function()
    local issues = lint.lint(fixtures.active_config())
    assert.are.equal(0, lint.count(issues, "error"))
    assert.are.equal(1, lint.count(issues, "warn"))
  end)

  it("rejects unknown top-level and rule keys, including old response config", function()
    local config = fixtures.config()
    config.version = "old"
    config.whitelist[1].response_schemas = { ["200"] = "old" }
    local issues = lint.lint(config)
    assert.is_true(has(issues, "error", "version"))
    assert.is_true(has(issues, "error", "response_schemas"))
  end)

  it("requires a stable unique rule id", function()
    local config = fixtures.config()
    config.whitelist[2].id = config.whitelist[1].id
    assert.is_true(has(lint.lint(config), "error", "重复"))
  end)

  it("accepts only exact paths and rejects query enablement", function()
    local config = fixtures.config()
    config.whitelist[1].pattern = "^/ai/knowledge/.*$"
    config.whitelist[2].allow_query = true
    local issues = lint.lint(config)
    assert.is_true(has(issues, "error", "正则"))
    assert.is_true(has(issues, "error", "query"))
  end)

  it("allows a bodyless rule and rejects a missing request schema reference", function()
    local config = fixtures.config()
    assert.is_nil(config.whitelist[1].request_schema)
    config.whitelist[2].request_schema = "missing"
    assert.is_true(has(lint.lint(config), "error", "missing"))
  end)

  it("requires additional_properties=false and valid required fields", function()
    local config = fixtures.config()
    config.schemas.knowledge_search_request.additional_properties = true
    config.schemas.knowledge_search_request.required[#config.schemas.knowledge_search_request.required + 1] = "tenant"
    local issues = lint.lint(config)
    assert.is_true(has(issues, "error", "additional_properties=false"))
    assert.is_true(has(issues, "error", "tenant"))
  end)

  it("rejects unknown formats, hooks, keywords, and incompatible constraints", function()
    local config = fixtures.config()
    local schema = config.schemas.knowledge_search_request
    schema.contract = "old-hook"
    schema.properties.query.format = "magic"
    schema.properties.query.maxLength = 4000
    schema.properties.top_k.max_length = 3
    local issues = lint.lint(config)
    assert.is_true(has(issues, "error", "contract"))
    assert.is_true(has(issues, "error", "magic"))
    assert.is_true(has(issues, "error", "maxLength"))
    assert.is_true(has(issues, "error", "max_length"))
  end)

  it("flags duplicate method+path routes", function()
    local config = fixtures.config()
    config.whitelist[#config.whitelist + 1] = {
      id = "DUPLICATE",
      methods = { "GET" },
      path = "/ai/knowledge/health",
    }
    assert.is_true(has(lint.lint(config), "error", "短路"))
  end)

  it("requires a positive request limit no larger than 16 KiB", function()
    local config = fixtures.config()
    config.max_request_body_bytes = 0
    assert.is_true(has(lint.lint(config), "error", "大于 0"))
    config.max_request_body_bytes = 16385
    assert.is_true(has(lint.lint(config), "error", "16384"))
  end)
end)
