-- handler 是 access_by_lua 胶水，依赖 ngx 运行时与 cjson；这里用 mock-ngx +
-- 极简真实 JSON 解析（spec/support/json）做集成测试，只对 ngx 这种外部运行时打桩。
-- 规则逻辑本身由 url_filter/body_validator/decision/factory 的纯逻辑测试覆盖。
describe("handler", function()
  local json = require("spec.support.json")
  local handler
  local captured

  local config = {
    whitelist = {
      { methods = { "POST" }, path = "/v1/chat/completions", body = "chat" },
      { methods = { "GET" }, path = "/v1/models" },
    },
    blacklist = { { pattern = "^/admin" }, { pattern = "^/v1/admin" } },
    forbidden_headers = { "x-openclaw-model" },
    schemas = {
      chat = {
        models = { "openclaw", "openclaw/default" },
        max_messages = 50,
        max_content_length = 8000,
        max_total_length = 32000,
        allowed_roles = { "system", "user", "assistant" },
        allowed_fields = { "model", "messages", "stream", "user", "temperature",
          "top_p", "frequency_penalty", "presence_penalty", "seed",
          "max_tokens", "max_completion_tokens", "stop" },
      },
    },
  }

  -- 用 Lua pattern 充当 ngx.re.find 的测试替身（对 ^/admin 这类简单 pattern 行为一致）
  local function set_ngx(req)
    captured = { status = nil, body = nil }
    _G.ngx = {
      INFO = "info",
      status = 200,
      header = {},
      var = { uri = req.uri, content_type = req.content_type, request_id = "rid-1" },
      log = function() end,
      say = function(s) captured.body = s end,
      exit = function(code) captured.status = code end,
      req = {
        get_method = function() return req.method end,
        read_body = function() end,
        get_body_data = function() return req.body_raw end,
        get_body_file = function() return req.body_file end,
        get_headers = function() return req.headers or {}, req.headers_err end,
      },
      re = {
        find = function(s, pat) return (string.find(s, pat)) end,
      },
    }
  end

  before_each(function()
    package.preload["cjson.safe"] = function() return json end
    package.loaded["cjson.safe"] = nil
    package.loaded["waf.handler"] = nil
    handler = require("waf.handler")
    handler.init(config)
  end)

  it("returns 403 not_in_whitelist for an unlisted path", function()
    set_ngx({ method = "GET", uri = "/v1/unknown" })
    handler.access()
    assert.are.equal(403, captured.status)
    assert.are.equal("not_in_whitelist", json.decode(captured.body).error)
  end)

  it("returns 403 blacklist for an admin path before whitelist", function()
    set_ngx({ method = "GET", uri = "/v1/admin" })
    handler.access()
    assert.are.equal(403, captured.status)
    assert.are.equal("blacklist", json.decode(captured.body).error)
  end)

  it("returns 415 for a non-json content type on POST", function()
    set_ngx({ method = "POST", uri = "/v1/chat/completions", content_type = "text/plain", body_raw = "hello" })
    handler.access()
    assert.are.equal(415, captured.status)
  end)

  it("returns 400 for an invalid json body", function()
    set_ngx({ method = "POST", uri = "/v1/chat/completions", content_type = "application/json", body_raw = "{bad" })
    handler.access()
    assert.are.equal(400, captured.status)
  end)

  it("returns 422 for a body that fails validation", function()
    set_ngx({
      method = "POST", uri = "/v1/chat/completions", content_type = "application/json",
      body_raw = json.encode({ model = "evil", messages = { { role = "user", content = "hi" } } }),
    })
    handler.access()
    assert.are.equal(422, captured.status)
    assert.are.equal("body", json.decode(captured.body).error)
  end)

  it("allows a valid chat request without writing a deny response", function()
    set_ngx({
      method = "POST", uri = "/v1/chat/completions", content_type = "application/json",
      body_raw = json.encode({ model = "openclaw", messages = { { role = "user", content = "hi" } } }),
    })
    handler.access()
    assert.is_nil(captured.status)
    assert.is_nil(captured.body)
  end)

  it("allows a whitelisted GET", function()
    set_ngx({ method = "GET", uri = "/v1/models" })
    handler.access()
    assert.is_nil(captured.status)
  end)

  it("returns 403 forbidden_header when x-openclaw-model is present (model allowlist bypass guard)", function()
    set_ngx({
      method = "POST", uri = "/v1/chat/completions", content_type = "application/json",
      headers = { ["x-openclaw-model"] = "openclaw/secret" },
      -- body 本身合法（openclaw 在该测试内联白名单里）,仅因夹带覆盖头被先行拦下
      body_raw = json.encode({ model = "openclaw", messages = { { role = "user", content = "hi" } } }),
    })
    handler.access()
    assert.are.equal(403, captured.status)
    assert.are.equal("forbidden_header", json.decode(captured.body).error)
  end)

  it("returns 413 body_too_large when the body spilled to a temp file (fail-closed)", function()
    set_ngx({
      method = "POST", uri = "/v1/chat/completions", content_type = "application/json",
      body_raw = nil, body_file = "/tmp/0001",   -- get_body_data()==nil 但落盘了
    })
    handler.access()
    assert.are.equal(413, captured.status)
    assert.are.equal("body_too_large", json.decode(captured.body).error)
  end)

  it("returns 400 too_many_headers when request headers were truncated (fail-closed)", function()
    set_ngx({
      method = "POST", uri = "/v1/chat/completions", content_type = "application/json",
      headers = {}, headers_err = "truncated",
      body_raw = json.encode({ model = "openclaw", messages = { { role = "user", content = "hi" } } }),
    })
    handler.access()
    assert.are.equal(400, captured.status)
    assert.are.equal("too_many_headers", json.decode(captured.body).error)
  end)
end)
