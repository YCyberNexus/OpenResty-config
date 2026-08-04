describe("policy_engine", function()
  local fixtures, engine

  before_each(function()
    fixtures = require("spec.fixtures")
    package.loaded["waf.policy_engine"] = nil
    engine = require("waf.policy_engine").new(fixtures.policies())
  end)

  it("gates and forwards bearer/API-key credentials without claiming backend validation", function()
    local rule = { auth_policy = "bearer", request = {} }
    local forwarded = assert(engine:validate_headers(rule, {
      authorization = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
      cookie = "not-forwarded",
    }))
    assert.is_not_nil(forwarded.authorization)
    assert.is_nil(forwarded.cookie)
    local value, err = engine:validate_headers(rule, { authorization = "Bearer bad token" })
    assert.is_nil(value)
    assert.are.equal("credential_format", err.reason)

    rule.auth_policy = "api_key"
    forwarded = assert(engine:validate_headers(rule, { ["x-api-key"] = "key-123" }))
    assert.are.equal("key-123", forwarded["x-api-key"])
  end)

  it("validates and forwards only declared business headers", function()
    local rule = { auth_policy = "network_only", request = { headers = {
      ["x-tenant-id"] = { required = true,
        schema = { type = "string", format = "slug", max_bytes = 64 } },
    } } }
    local forwarded = assert(engine:validate_headers(rule,
      { ["x-tenant-id"] = "team-a", cookie = "secret" }))
    assert.are.equal("team-a", forwarded["x-tenant-id"])
    assert.is_nil(forwarded.cookie)
    local value, err = engine:validate_headers(rule, {})
    assert.is_nil(value)
    assert.are.equal("required_header_missing", err.reason)
  end)

  it("implements a conservative read-only Cypher policy", function()
    local check = require("waf.policy_engine").cypher_is_read_only
    assert.is_true(check("MATCH (n) WHERE n.name = 'DELETE' RETURN n"))
    assert.is_true(check("/* CREATE ignored in comment */ MATCH (n) RETURN n"))
    assert.is_false(check("MATCH (n) SET n.secret = 1 RETURN n"))
    assert.is_false(check("CALL db.labels()"))
    assert.is_false(check("MATCH (n) RETURN n; DELETE n"))
    assert.is_false(check("MATCH (n) WHERE n.name = 'unterminated RETURN n"))
  end)

  it("applies a named read-only policy to the configured JSON field", function()
    local rule = { auth_policy = "network_only",
      request = { policies = { "cypher_read_only_v1" } } }
    assert.is_true(engine:validate_request_policies(rule, { cypher = "MATCH (n) RETURN n" }))
    local ok, err = engine:validate_request_policies(rule,
      { cypher = "MATCH (n) DELETE n" })
    assert.is_nil(ok)
    assert.are.equal("request_policy", err.reason)
  end)
end)
