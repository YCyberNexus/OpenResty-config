describe("rules_lint V2", function()
  local lint, fixtures, policies

  before_each(function()
    package.loaded["waf.rules_lint"] = nil
    lint = require("waf.rules_lint")
    fixtures = require("spec.fixtures")
    policies = fixtures.policies()
  end)

  local function has(issues, level, text)
    for _, issue in ipairs(issues) do
      if issue.level == level and (tostring(issue.where):find(text, 1, true)
        or tostring(issue.msg):find(text, 1, true)) then return true end
    end
    return false
  end

  local function check(config, routes)
    return lint.lint(config, routes or fixtures.routes_for(config), policies)
  end

  it("passes a complete V2 rule/route/policy set", function()
    local config = fixtures.config()
    local issues = lint.lint(config, fixtures.config_routes(), policies)
    assert.are.equal(0, lint.count(issues, "error"))
    assert.are.equal(0, lint.count(issues, "warn"))
  end)

  it("accepts deny-all and rejects V1 or unknown fields", function()
    local config = fixtures.config()
    config.whitelist = {}
    config.schemas = {}
    local routes = { version = 2, required_node_roles = { "dev" }, nodes = { dev = {} } }
    local issues = lint.lint(config, routes, policies)
    assert.are.equal(0, lint.count(issues, "error"))
    assert.is_true(has(issues, "warn", "白名单为空"))

    config = fixtures.config()
    config.max_request_body_bytes = 16384
    config.whitelist[2].request_schema = "knowledge_search_request"
    issues = check(config)
    assert.is_true(has(issues, "error", "max_request_body_bytes"))
    assert.is_true(has(issues, "error", "V1 字段已废弃"))
  end)

  it("requires stable IDs, exact hosts, methods, and authentication policy", function()
    local config = fixtures.config()
    config.whitelist[2].id = config.whitelist[1].id
    config.whitelist[1].host = "*.Example.COM:80"
    config.whitelist[1].methods = { "TRACE" }
    config.whitelist[1].auth_policy = "missing"
    local issues = check(config)
    assert.is_true(has(issues, "error", "id 重复"))
    assert.is_true(has(issues, "error", "host"))
    assert.is_true(has(issues, "error", "method"))
    assert.is_true(has(issues, "error", "认证门禁"))
  end)

  it("supports multiple typed path parameters and rejects ambiguous routes", function()
    local config = fixtures.config()
    local route = {
      id = "MULTI-PARAM",
      host = "127.0.0.1",
      methods = { "GET" },
      path_template = "/tenants/{tenant_id}/assets/{asset_id}",
      path_parameters = {
        tenant_id = { type = "string", format = "slug" },
        asset_id = { type = "string", format = "uuid" },
      },
      transport = "buffered",
      auth_policy = "network_only",
      responses = config.whitelist[1].responses,
    }
    config.whitelist[#config.whitelist + 1] = route
    assert.are.equal(0, lint.count(check(config), "error"))

    config.whitelist[#config.whitelist + 1] = {
      id = "AMBIGUOUS", host = "127.0.0.1", methods = { "GET" },
      path_template = "/tenants/{name}/assets/{uuid}",
      path_parameters = {
        name = { type = "string", format = "slug" },
        uuid = { type = "string", format = "uuid" },
      },
      transport = "buffered", auth_policy = "network_only",
      responses = config.whitelist[1].responses,
    }
    assert.is_true(has(check(config), "error", "重叠"))
  end)

  it("reserves internal proxy prefixes and rejects malformed templates", function()
    local config = fixtures.config()
    config.whitelist[1].path = "/__waf_stream/long/private"
    assert.is_true(has(check(config), "error", "保留"))
    config = fixtures.config()
    config.whitelist[1].path = nil
    config.whitelist[1].path_template = "/users/prefix-{user_id}"
    config.whitelist[1].path_parameters = {
      user_id = { type = "string", format = "slug" },
    }
    assert.is_true(has(check(config), "error", "独立命名路径段"))
    config.whitelist[1].path_template = "/__waf_upstream/{user_id}"
    assert.is_true(has(check(config), "error", "保留"))
  end)

  it("allows typed Query schemas and rejects open or nested Query", function()
    local config = fixtures.config()
    config.schemas.health_query = {
      type = "object", additional_properties = false,
      required = { "verbose" },
      properties = {
        verbose = { type = "boolean" },
        tag = { type = "array", max_items = 5, items = { type = "string", max_bytes = 64 } },
      },
    }
    config.whitelist[1].request = { query_schema = "health_query" }
    assert.are.equal(0, lint.count(check(config), "error"))
    config.schemas.health_query.additional_properties = true
    config.schemas.health_query.properties.tag.items = {
      type = "object", additional_properties = false, properties = {},
    }
    local issues = check(config)
    assert.is_true(has(issues, "error", "Query 必须 additional_properties=false"))
    assert.is_true(has(issues, "error", "Query 只支持"))
  end)

  it("allows explicitly bounded forwarded headers and rejects managed headers", function()
    local config = fixtures.config()
    config.whitelist[1].request = {
      headers = {
        ["x-tenant-id"] = {
          required = true,
          schema = { type = "string", format = "slug", max_bytes = 64 },
        },
      },
    }
    assert.are.equal(0, lint.count(check(config), "error"))
    config.whitelist[1].request.headers["content-length"] = {
      schema = { type = "string", max_bytes = 16 },
    }
    assert.is_true(has(check(config), "error", "WAF/Nginx 管理"))
  end)

  it("supports buffered JSON/text/binary and explicit streaming policies", function()
    local config = fixtures.config()
    config.schemas.plain_text = { type = "string", max_bytes = 4096 }
    config.whitelist[1].transport = "stream"
    config.whitelist[1].timeout_profile = "long"
    config.whitelist[1].responses[200].body = {
      mode = "stream", media_types = { "text/event-stream" }, max_body_bytes = 10485760,
      audit_body = false,
    }
    local issues = check(config)
    assert.are.equal(0, lint.count(issues, "error"))
    assert.is_true(has(issues, "warn", "流式模式"))

    config = fixtures.config()
    config.whitelist[2].request.body = {
      mode = "binary", required = true, media_types = { "multipart/form-data" },
      max_body_bytes = 1048576, audit_body = false,
    }
    assert.are.equal(0, lint.count(check(config), "error"))
  end)

  it("enforces global and per-route buffered/stream size ceilings", function()
    local config = fixtures.config()
    config.limits.max_buffered_request_body_bytes = 1048577
    assert.is_true(has(check(config), "error", "运行时硬上限"))
    config = fixtures.config()
    config.whitelist[2].request.body.max_body_bytes = 1048577
    assert.is_true(has(check(config), "error", "全局正文上限"))
    config = fixtures.config()
    config.limits.max_stream_response_body_bytes = 268435457
    assert.is_true(has(check(config), "error", "运行时硬上限"))
  end)

  it("requires fixed IPv4 routes for every production role and referenced Host", function()
    local config = fixtures.active_config()
    local routes = fixtures.active_routes()
    routes.nodes.yellow["kb.pxsemic.tech"] = nil
    local issues = lint.lint(config, routes, policies)
    assert.is_true(has(issues, "error", "缺少固定下一跳"))
    routes = fixtures.active_routes()
    routes.nodes.yellow["kb.pxsemic.tech"].address = "backend.internal"
    assert.is_true(has(lint.lint(config, routes, policies), "error", "固定规范 IPv4"))
  end)

  it("requires status-specific response body policies and known schemas", function()
    local config = fixtures.config()
    config.whitelist[2].responses[200].body.schema = "missing"
    config.whitelist[2].responses[201] = {}
    local issues = check(config)
    assert.is_true(has(issues, "error", "正文 schema"))
    assert.is_true(has(issues, "error", "body 策略"))
  end)

  it("detects unsafe reusable policy definitions", function()
    local config = fixtures.config()
    local bad = fixtures.policies()
    bad.auth.bearer.max_bytes = 10000
    bad.auth.bearer.header = "host"
    bad.timeout_profiles.arbitrary = true
    bad.request_policies.cypher_read_only_v1.kind = "lua_hook"
    local issues = lint.lint(config, fixtures.config_routes(), bad)
    assert.is_true(has(issues, "error", "1..8192"))
    assert.is_true(has(issues, "error", "Bearer/Basic"))
    assert.is_true(has(issues, "error", "fast/standard/long"))
    assert.is_true(has(issues, "error", "未知内置请求策略"))
  end)
end)
