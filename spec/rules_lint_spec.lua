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

  it("passes a complete operations example with zero errors and warnings", function()
    local issues = lint.lint(fixtures.config())
    assert.are.equal(0, lint.count(issues, "error"))
    assert.are.equal(0, lint.count(issues, "warn"))
  end)

  it("keeps examples and unconfigured defaults out of production deployment", function()
    local example = fixtures.config()
    local active = fixtures.active_config()
    assert.is_true(has(lint.lint(example, { production = true }), "error", "示例"))
    assert.is_true(has(lint.lint(active, { production = true }), "error", "生产部署"))

    example.example = false
    example.version = "CHANGE-2026-001"
    assert.are.equal(0, lint.count(lint.lint(example, { production = true }), "error"))

    example.example = nil
    assert.is_true(has(lint.lint(example, { production = true }), "error", "example=false"))
  end)

  it("rejects unknown top-level and URL-rule keys", function()
    local config = fixtures.config()
    config.maxRequestBodyBytes = 123
    config.whitelist[1].response_schema = "knowledge_health_response"
    local issues = lint.lint(config)
    assert.is_true(has(issues, "error", "maxRequestBodyBytes"))
    assert.is_true(has(issues, "error", "response_schema"))
  end)

  it("requires a non-empty operations direction marker", function()
    local config = fixtures.config()
    config.direction = ""
    assert.is_true(has(lint.lint(config), "error", "方向"))
  end)

  it("requires a stable unique rule id", function()
    local config = fixtures.config()
    config.whitelist[2].id = config.whitelist[1].id
    assert.is_true(has(lint.lint(config), "error", "重复"))
  end)

  it("rejects regex paths in the cross-zone whitelist", function()
    local config = fixtures.config()
    config.whitelist[1].pattern = "^/ai/knowledge/.*$"
    assert.is_true(has(lint.lint(config), "error", "正则"))
  end)

  it("does not infer body policy from the HTTP method", function()
    local config = fixtures.config()
    config.whitelist[2].request_schema = nil
    assert.are.equal(0, lint.count(lint.lint(config), "error"))
  end)

  it("requires an explicit response schema map", function()
    local config = fixtures.config()
    config.whitelist[1].response_schemas = nil
    assert.is_true(has(lint.lint(config), "error", "响应状态"))
  end)

  it("flags request or response references to missing schemas", function()
    local config = fixtures.config()
    config.whitelist[2].request_schema = "missing"
    config.whitelist[1].response_schemas["200"] = "missing_response"
    local issues = lint.lint(config)
    assert.is_true(has(issues, "error", "missing"))
    assert.is_true(has(issues, "error", "missing_response"))
  end)

  it("requires additional_properties=false on every object", function()
    local config = fixtures.config()
    config.schemas.knowledge_search_response.properties.results.items.additional_properties = true
    assert.is_true(has(lint.lint(config), "error", "additional_properties=false"))
  end)

  it("flags required fields that have no property definition", function()
    local config = fixtures.config()
    config.schemas.knowledge_search_request.required[#config.schemas.knowledge_search_request.required + 1] = "tenant"
    assert.is_true(has(lint.lint(config), "error", "tenant"))
  end)

  it("flags unknown formats and removed business contract hooks", function()
    local config = fixtures.config()
    config.schemas.knowledge_search_request.properties.query.format = "magic"
    config.schemas.knowledge_health_response.contract = "unknown"
    local issues = lint.lint(config)
    assert.is_true(has(issues, "error", "magic"))
    assert.is_true(has(issues, "error", "contract"))
  end)

  it("rejects unknown schema keywords instead of silently ignoring typos", function()
    local config = fixtures.config()
    config.schemas.knowledge_search_request.properties.query.maxLength = 4000
    assert.is_true(has(lint.lint(config), "error", "maxLength"))
  end)

  it("rejects schema constraints attached to an incompatible type", function()
    local config = fixtures.config()
    config.schemas.knowledge_search_request.properties.top_k.max_length = 3
    assert.is_true(has(lint.lint(config), "error", "max_length"))
  end)

  it("flags duplicate method+path routes", function()
    local config = fixtures.config()
    config.whitelist[#config.whitelist + 1] = {
      id = "DUPLICATE",
      methods = { "GET" },
      path = "/ai/knowledge/health",
      response_schemas = { ["200"] = "knowledge_health_response" },
    }
    assert.is_true(has(lint.lint(config), "error", "短路"))
  end)

  it("requires positive request and response byte limits", function()
    local config = fixtures.config()
    config.max_response_body_bytes = 0
    assert.is_true(has(lint.lint(config), "error", "max_response_body_bytes"))
  end)

  it("rejects a forbidden-header wildcard outside the final position", function()
    local config = fixtures.config()
    config.forbidden_headers[#config.forbidden_headers + 1] = "x-*-override"
    assert.is_true(has(lint.lint(config), "error", "通配符"))
  end)

  it("rejects unrestricted query-string enablement", function()
    local config = fixtures.config()
    config.whitelist[1].allow_query = true
    assert.is_true(has(lint.lint(config), "error", "query"))
  end)
end)
