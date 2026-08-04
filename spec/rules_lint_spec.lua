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
    local issues = lint.lint({
      max_request_body_bytes = 16384,
      max_response_body_bytes = 1048576,
      whitelist = {},
      schemas = {},
    })
    assert.are.equal(0, lint.count(issues, "error"))
    assert.are.equal(1, lint.count(issues, "warn"))
  end)

  it("rejects unknown top-level and obsolete response keys", function()
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

  it("requires an exact lowercase host without a port or wildcard", function()
    local config = fixtures.config()
    config.whitelist[1].host = "Knowledge.EXAMPLE.internal:8080"
    assert.is_true(has(lint.lint(config), "error", "host"))
    config.whitelist[1].host = "*.example.internal"
    assert.is_true(has(lint.lint(config), "error", "host"))
  end)

  it("accepts exact paths or a terminal UUID template and rejects arbitrary patterns", function()
    local config = fixtures.config()
    config.whitelist[#config.whitelist + 1] = {
      id = "ASSET",
      host = "127.0.0.1",
      methods = { "GET" },
      path_template = "/ai/knowledge/assets/{uuid}",
      responses = {
        [200] = { schema = "knowledge_health_response", max_body_bytes = 16384 },
      },
    }
    assert.are.equal(0, lint.count(lint.lint(config), "error"))

    config.whitelist[1].pattern = "^/ai/knowledge/.*$"
    config.whitelist[2].allow_query = true
    config.whitelist[3].path_template = "/ai/knowledge/assets/{asset_id}"
    local issues = lint.lint(config)
    assert.is_true(has(issues, "error", "正则"))
    assert.is_true(has(issues, "error", "query"))
    assert.is_true(has(issues, "error", "{uuid}"))
  end)

  it("reserves the internal response-capture path prefix", function()
    local config = fixtures.config()
    config.whitelist[1].path = "/__waf_upstream/ai/knowledge/health"
    assert.is_true(has(lint.lint(config), "error", "保留"))

    config = fixtures.config()
    config.whitelist[1].path = nil
    config.whitelist[1].path_template = "/__waf_upstream/assets/{uuid}"
    assert.is_true(has(lint.lint(config), "error", "保留"))
  end)

  it("allows a bodyless rule and rejects a missing request schema reference", function()
    local config = fixtures.config()
    assert.is_nil(config.whitelist[1].request_schema)
    config.whitelist[2].request_schema = "missing"
    assert.is_true(has(lint.lint(config), "error", "missing"))
  end)

  it("requires explicit additional_properties and warns on arbitrary fields", function()
    local config = fixtures.config()
    config.schemas.knowledge_search_request.additional_properties = nil
    config.schemas.knowledge_search_request.required[#config.schemas.knowledge_search_request.required + 1] = "tenant"
    local issues = lint.lint(config)
    assert.is_true(has(issues, "error", "additional_properties"))
    assert.is_true(has(issues, "error", "tenant"))

    config = fixtures.config()
    config.schemas.knowledge_search_request.additional_properties = true
    issues = lint.lint(config)
    assert.are.equal(0, lint.count(issues, "error"))
    assert.is_true(has(issues, "warn", "任意未登记字段"))
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

  it("allows the same method/path on different hosts and rejects a duplicate host route", function()
    local config = fixtures.config()
    local same_path = {
      id = "OTHER-HOST",
      host = "other.example.internal",
      methods = { "GET" },
      path = "/ai/knowledge/health",
      responses = {
        [200] = { schema = "knowledge_health_response", max_body_bytes = 16384 },
      },
    }
    config.whitelist[#config.whitelist + 1] = same_path
    assert.are.equal(0, lint.count(lint.lint(config), "error"))
    config.whitelist[#config.whitelist + 1] = {
      id = "DUPLICATE",
      host = "127.0.0.1",
      methods = { "GET" },
      path = "/ai/knowledge/health",
      responses = {
        [200] = { schema = "knowledge_health_response", max_body_bytes = 16384 },
      },
    }
    assert.is_true(has(lint.lint(config), "error", "短路"))
  end)

  it("rejects an exact route that overlaps a UUID path template", function()
    local config = fixtures.config()
    config.whitelist[#config.whitelist + 1] = {
      id = "ASSET-TEMPLATE",
      host = "127.0.0.1",
      methods = { "GET" },
      path_template = "/ai/knowledge/assets/{uuid}",
      responses = {
        [200] = { schema = "knowledge_health_response", max_body_bytes = 16384 },
      },
    }
    config.whitelist[#config.whitelist + 1] = {
      id = "ASSET-EXACT",
      host = "127.0.0.1",
      methods = { "GET" },
      path = "/ai/knowledge/assets/f440c18e-a281-44bc-a878-8aa92b620879",
      responses = {
        [200] = { schema = "knowledge_health_response", max_body_bytes = 16384 },
      },
    }
    assert.is_true(has(lint.lint(config), "error", "重叠"))
  end)

  it("requires a positive request limit no larger than 128 KiB", function()
    local config = fixtures.config()
    config.max_request_body_bytes = 0
    assert.is_true(has(lint.lint(config), "error", "大于 0"))
    config.max_request_body_bytes = 131073
    assert.is_true(has(lint.lint(config), "error", "131072"))
  end)

  it("requires bounded, status-specific response schemas", function()
    local config = fixtures.config()
    config.whitelist[2].responses[200].schema = "missing"
    config.whitelist[2].responses[201] = { schema = "knowledge_search_response", max_body_bytes = 1048577 }
    local issues = lint.lint(config)
    assert.is_true(has(issues, "error", "missing"))
    assert.is_true(has(issues, "error", "max_body_bytes"))

    config = fixtures.config()
    config.whitelist[2].responses = {}
    assert.is_true(has(lint.lint(config), "error", "responses"))
  end)

  it("caps the global response buffer at one MiB", function()
    local config = fixtures.config()
    config.max_response_body_bytes = 0
    assert.is_true(has(lint.lint(config), "error", "大于 0"))
    config.max_response_body_bytes = 1048577
    assert.is_true(has(lint.lint(config), "error", "1048576"))
  end)
end)
