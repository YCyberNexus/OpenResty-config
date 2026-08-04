describe("handler V2", function()
  local fixtures, json, handler, captured

  local function set_ngx(request)
    request = request or {}
    captured = {
      body = nil, exit_status = nil, forward_body = nil, forward_file = nil,
      capture_uri = nil, capture_opts = nil, exec_uri = nil, exec_args = nil,
      read_body_calls = 0,
    }
    local headers = {}
    for key, value in pairs(request.headers or {}) do headers[key] = value end
    if request.content_type and headers["content-type"] == nil then
      headers["content-type"] = request.content_type
    end
    if request.body_raw and request.omit_content_length ~= true
      and headers["content-length"] == nil then
      headers["content-length"] = tostring(#request.body_raw)
    end
    local current_body = request.body_raw
    local function normalized(name) return tostring(name):lower():gsub("_", "-") end
    _G.ngx = {
      status = 200,
      header = {},
      arg = { nil, false },
      ctx = {},
      var = {
        host = request.host or "127.0.0.1",
        uri = request.uri,
        request_uri = request.request_uri or (request.uri
          .. ((request.query_present or request.args ~= nil) and "?" or "")
          .. (request.args or "")),
        args = request.args,
        is_args = request.force_empty_is_args and ""
          or (request.query_present and "?" or (request.args ~= nil and "?" or "")),
        content_type = request.content_type,
        request_id = "local-rid-1",
        waf_trace_id = "trace-rid-1",
        upstream_addr = request.upstream_addr or "192.0.2.10:6789",
      },
      print = function(value) captured.body = (captured.body or "") .. tostring(value) end,
      exit = function(status) captured.exit_status = status end,
      exec = function(uri, args) captured.exec_uri, captured.exec_args = uri, args end,
      sha256_bin = function() return string.rep("\1", 32) end,
      HTTP_GET = 2, HTTP_POST = 8, HTTP_PUT = 16, HTTP_DELETE = 32,
      HTTP_PATCH = 16384, HTTP_HEAD = 4, HTTP_OPTIONS = 512,
      location = {
        capture = function(uri, opts)
          captured.capture_uri, captured.capture_opts = uri, opts
          return request.upstream_response
        end,
      },
      req = {
        get_method = function() return request.method end,
        read_body = function() captured.read_body_calls = captured.read_body_calls + 1 end,
        get_body_data = function() return current_body end,
        get_body_file = function() return request.body_file end,
        get_headers = function() return headers, request.headers_err end,
        clear_header = function(name)
          local wanted = normalized(name)
          for key in pairs(headers) do if normalized(key) == wanted then headers[key] = nil end end
        end,
        set_header = function(name, value) headers[normalized(name)] = value end,
        set_body_data = function(value) current_body = value captured.forward_body = value end,
        set_body_file = function(value) captured.forward_file = value end,
      },
    }
    captured.forward_headers = headers
  end

  local function init(config, routes, role)
    config = config or fixtures.config()
    routes = routes or fixtures.routes_for(config)
    handler.init(config, routes, fixtures.policies(), role or "dev")
  end

  local function valid_search_request(overrides)
    local value = {
      host = "127.0.0.1", method = "POST", uri = "/ai/knowledge/search",
      content_type = "application/json", body_raw = json.encode(fixtures.search_request(overrides)),
    }
    return value
  end

  local function valid_search_response(overrides)
    overrides = overrides or {}
    return {
      status = overrides.status or 200,
      body = overrides.body or json.encode(fixtures.search_response()),
      header = overrides.header or {
        ["Content-Type"] = "application/json; charset=utf-8",
        ["X-WAF-Internal-Upstream-Addr"] = "192.0.2.10:6789",
      },
      truncated = overrides.truncated,
    }
  end

  before_each(function()
    fixtures = require("spec.fixtures")
    json = fixtures.json
    package.preload["cjson.safe"] = function() return json end
    package.loaded["cjson.safe"] = nil
    package.loaded["waf.handler"] = nil
    handler = require("waf.handler")
    init()
  end)

  it("refuses an invalid combined configuration", function()
    local invalid = fixtures.config()
    invalid.whitelist[2].request.body.schema = "missing"
    assert.is_false(pcall(function() init(invalid) end))
  end)

  it("default-denies an unlisted host/path before reading or parsing a body", function()
    set_ngx({ method = "POST", uri = "/not-listed", content_type = "text/plain", body_raw = "x" })
    handler.access()
    assert.are.equal(403, captured.exit_status)
    assert.are.equal("not_in_whitelist", json.decode(captured.body).error)
    assert.are.equal(0, captured.read_body_calls)

    set_ngx({ host = "other.internal", method = "GET", uri = "/ai/knowledge/health" })
    handler.access()
    assert.are.equal("not_in_whitelist", json.decode(captured.body).error)
  end)

  it("rejects unconfigured Query including a bare question mark", function()
    set_ngx({ method = "GET", uri = "/ai/knowledge/health", args = "debug=true" })
    handler.access()
    assert.are.equal("query_not_allowed", json.decode(captured.body).error)
    set_ngx({ method = "GET", uri = "/ai/knowledge/health", args = "",
      query_present = true, force_empty_is_args = true })
    handler.access()
    assert.are.equal("query_not_allowed", json.decode(captured.body).error)
  end)

  it("normalizes typed Query and forwards only its canonical form", function()
    local config = fixtures.config()
    config.schemas.health_query = {
      type = "object", additional_properties = false,
      required = { "page", "enabled" },
      properties = {
        page = { type = "integer", minimum = 1, maximum = 99 },
        enabled = { type = "boolean" },
        tag = { type = "array", max_items = 3, items = { type = "string", max_bytes = 20 } },
      },
    }
    config.whitelist[1].request = { query_schema = "health_query" }
    init(config)
    set_ngx({ method = "GET", uri = "/ai/knowledge/health",
      args = "tag=b&enabled=true&page=02&tag=a" })
    handler.access()
    assert.is_nil(captured.exit_status)
    assert.are.equal("enabled=true&page=2&tag=b&tag=a", ngx.var.waf_forward_query)
    assert.are.equal("/ai/knowledge/health?enabled=true&page=2&tag=b&tag=a",
      ngx.var.waf_upstream_uri)

    set_ngx({ method = "GET", uri = "/ai/knowledge/health", args = "page=1&page=2&enabled=true" })
    handler.access()
    assert.are.equal("duplicate_query_parameter", json.decode(captured.body).error)
  end)

  it("validates media type, size, JSON and records normalized bodies", function()
    local accepted = valid_search_request()
    accepted.content_type = "Application/JSON; charset=utf-8"
    set_ngx(accepted)
    handler.access()
    assert.is_nil(captured.exit_status)
    assert.are.equal("allow_request", ngx.var.waf_action)
    assert.are.same(fixtures.search_request(), json.decode(captured.forward_body))
    assert.are.equal(accepted.body_raw, ngx.var.waf_request_body)
    assert.are.equal(captured.forward_body, ngx.var.waf_forward_body)

    local rejected = valid_search_request()
    rejected.content_type = "application/jsonp"
    set_ngx(rejected)
    handler.access()
    assert.are.equal(415, captured.exit_status)

    local invalid = valid_search_request()
    invalid.body_raw = '{"query":"q"} trailing'
    set_ngx(invalid)
    handler.access()
    assert.are.equal("invalid_json", json.decode(captured.body).error)

    local oversized = valid_search_request()
    oversized.body_raw = string.rep("x", 16385)
    set_ngx(oversized)
    handler.access()
    assert.are.equal(413, captured.exit_status)
  end)

  it("reads a bounded disk-buffered JSON body and rejects an oversized file", function()
    local request = valid_search_request()
    request.body_raw = nil
    request.body_file = os.tmpname()
    local file = assert(io.open(request.body_file, "wb"))
    file:write(json.encode(fixtures.search_request()))
    file:close()
    request.headers = { ["content-length"] = tostring(100) }
    set_ngx(request)
    handler.access()
    os.remove(request.body_file)
    assert.is_nil(captured.exit_status)
    assert.is_not_nil(captured.forward_body)

    local config = fixtures.config()
    config.whitelist[2].request.body.max_body_bytes = 8
    init(config)
    request = valid_search_request()
    request.body_raw = nil
    request.body_file = os.tmpname()
    file = assert(io.open(request.body_file, "wb"))
    file:write("0123456789")
    file:close()
    request.headers = { ["content-length"] = "10" }
    set_ngx(request)
    handler.access()
    os.remove(request.body_file)
    assert.are.equal("request_body_too_large", json.decode(captured.body).error)
  end)

  it("forwards only declared headers and applies bearer syntax gating", function()
    local config = fixtures.config()
    config.whitelist[1].auth_policy = "bearer"
    config.whitelist[1].request = {
      headers = {
        ["x-tenant-id"] = { required = true,
          schema = { type = "string", format = "slug", max_bytes = 64 } },
      },
    }
    init(config)
    set_ngx({ method = "GET", uri = "/ai/knowledge/health", headers = {
      authorization = "Bearer abc.def_123", ["x-tenant-id"] = "team-a",
      ["x-http-method-override"] = "DELETE", cookie = "secret=not-forwarded",
    } })
    handler.access()
    assert.is_nil(captured.exit_status)
    assert.are.equal("Bearer abc.def_123", captured.forward_headers.authorization)
    assert.are.equal("team-a", captured.forward_headers["x-tenant-id"])
    assert.is_nil(captured.forward_headers.cookie)
    assert.is_nil(captured.forward_headers["x-http-method-override"])

    set_ngx({ method = "GET", uri = "/ai/knowledge/health", headers = {
      authorization = "bad token", ["x-tenant-id"] = "team-a",
    } })
    handler.access()
    assert.are.equal(401, captured.exit_status)
    assert.are.equal("credential_format", json.decode(captured.body).error)
  end)

  it("rejects a body on a bodyless route", function()
    set_ngx({ method = "GET", uri = "/ai/knowledge/health", body_raw = "hidden",
      omit_content_length = true })
    handler.access()
    assert.are.equal("unexpected_body", json.decode(captured.body).error)
  end)

  it("matches a multi-capability named UUID path without broad prefix access", function()
    init(fixtures.active_config(), fixtures.active_routes(), "blue")
    local uri = "/ai/knowledge/assets/f440c18e-a281-44bc-a878-8aa92b620879"
    set_ngx({ host = "kb.pxsemic.tech", method = "GET", uri = uri,
      upstream_response = { status = 200, body = json.encode(fixtures.asset_response()),
        header = { ["Content-Type"] = "application/json" } } })
    handler.access()
    handler.proxy()
    assert.are.equal(200, captured.exit_status)
    assert.are.equal("/__waf_upstream/standard" .. uri, captured.capture_uri)
    assert.are.equal("BY-002-KB-ASSET", ngx.var.waf_rule_id)
    assert.are.equal("http://10.64.9.2:80", ngx.var.waf_upstream_origin)
    assert.are.equal("", ngx.var.waf_response_body)
    assert.are.equal(64, #ngx.var.waf_response_body_sha256)

    set_ngx({ host = "kb.pxsemic.tech", method = "GET",
      uri = "/ai/knowledge/assets/not-a-uuid" })
    handler.access()
    assert.are.equal("not_in_whitelist", json.decode(captured.body).error)
  end)

  it("captures, validates, normalizes, and audits a buffered response", function()
    local request = valid_search_request()
    request.upstream_response = valid_search_response()
    set_ngx(request)
    handler.access()
    handler.proxy()
    assert.are.equal(200, captured.exit_status)
    assert.are.equal("/__waf_upstream/standard/ai/knowledge/search", captured.capture_uri)
    assert.are.equal(8, captured.capture_opts.method)
    assert.is_nil(captured.capture_opts.copy_all_vars)
    assert.is_nil(captured.capture_opts.share_all_vars)
    assert.are.equal(ngx.ctx, captured.capture_opts.ctx)
    assert.are.equal("http://127.0.0.1:18080", captured.capture_opts.vars.waf_upstream_origin)
    assert.are.equal("/ai/knowledge/search", captured.capture_opts.vars.waf_upstream_uri)
    assert.are.equal("allow_response", ngx.var.waf_action)
    assert.are.equal("knowledge_search_response", ngx.var.waf_response_schema)
    assert.are.equal("192.0.2.10:6789", ngx.var.waf_upstream_addr)
    assert.are.same(fixtures.search_response(), json.decode(captured.body))
  end)

  it("fails closed for unlisted status, capture failure, media, encoding and schema drift", function()
    local cases = {
      { response = valid_search_response({ status = 201, body = '{"secret":"must-not-leak"}' }),
        reason = "response_status_not_allowed" },
      { response = valid_search_response({ header = { ["Content-Type"] = "text/plain" } }),
        reason = "response_unsupported_media_type" },
      { response = valid_search_response({ body = "not-json" }), reason = "invalid_upstream_json" },
      { response = valid_search_response({ body = '{"query":"missing fields"}' }), reason = "response_body" },
      { response = valid_search_response({ header = { ["Content-Type"] = "application/json",
          ["Content-Encoding"] = "gzip" } }), reason = "response_content_encoding_not_allowed" },
      { response = valid_search_response({ truncated = true }), reason = "response_body_too_large" },
    }
    for _, case in ipairs(cases) do
      local request = valid_search_request()
      request.upstream_response = case.response
      set_ngx(request)
      handler.access()
      handler.proxy()
      assert.are.equal(502, captured.exit_status)
      assert.are.equal(case.reason, json.decode(captured.body).error)
      if case.reason == "response_status_not_allowed" then
        assert.is_nil(captured.body:find("must-not-leak", 1, true))
      end
    end

    local request = valid_search_request()
    set_ngx(request)
    ngx.location.capture = function() error("synthetic capture failure") end
    handler.access()
    handler.proxy()
    assert.are.equal("upstream_capture_failed", json.decode(captured.body).error)
  end)

  it("supports validated text and bounded binary buffered responses", function()
    local config = fixtures.config()
    config.schemas.health_text = { type = "string", min_length = 1, max_bytes = 100 }
    config.whitelist[1].responses[200].body = {
      mode = "text", media_types = { "text/plain" }, schema = "health_text", max_body_bytes = 100,
    }
    init(config)
    set_ngx({ method = "GET", uri = "/ai/knowledge/health",
      upstream_response = { status = 200, body = "healthy",
        header = { ["Content-Type"] = "text/plain; charset=utf-8" } } })
    handler.access()
    handler.proxy()
    assert.are.equal("healthy", captured.body)

    config = fixtures.config()
    config.whitelist[1].responses[200].body = {
      mode = "binary", media_types = { "application/pdf" }, max_body_bytes = 100,
    }
    init(config)
    set_ngx({ method = "GET", uri = "/ai/knowledge/health",
      upstream_response = { status = 200, body = "%PDF-test",
        header = { ["Content-Type"] = "application/pdf" } } })
    handler.access()
    handler.proxy()
    assert.are.equal("%PDF-test", captured.body)
  end)

  it("uses explicit stream transport for SSE and audits bytes/hash without buffering", function()
    local config = fixtures.config()
    config.whitelist[1].transport = "stream"
    config.whitelist[1].timeout_profile = "long"
    config.whitelist[1].responses[200].body = {
      mode = "stream", media_types = { "text/event-stream" }, max_body_bytes = 1000,
      audit_body = false,
    }
    init(config)
    set_ngx({ method = "GET", uri = "/ai/knowledge/health" })
    handler.access()
    handler.proxy()
    assert.are.equal("/__waf_stream/long/ai/knowledge/health", captured.exec_uri)
    ngx.status = 200
    ngx.header = { ["Content-Type"] = "text/event-stream" }
    handler.upstream_header_filter()
    ngx.arg = { "data: ok\n\n", true }
    handler.stream_body_filter()
    assert.are.equal("allow_response", ngx.var.waf_action)
    assert.are.equal(tostring(#"data: ok\n\n"), ngx.var.waf_response_body_bytes)
    assert.are.equal("", ngx.var.waf_response_body)
  end)

  it("supports a large streamed multipart body without copying it into audit logs", function()
    local config = fixtures.config()
    config.whitelist[2].transport = "stream"
    config.whitelist[2].request.body = {
      mode = "binary", required = true, media_types = { "multipart/form-data" },
      max_body_bytes = 1048576, audit_body = false,
    }
    for _, response in pairs(config.whitelist[2].responses) do
      response.body = { mode = "stream", media_types = { "application/json" },
        max_body_bytes = 1048576, audit_body = false }
    end
    init(config)
    local path = os.tmpname()
    local file = assert(io.open(path, "wb"))
    file:write(string.rep("x", 200000))
    file:close()
    set_ngx({ method = "POST", uri = "/ai/knowledge/search", body_file = path,
      content_type = "multipart/form-data; boundary=safe",
      headers = { ["content-length"] = "200000" } })
    handler.access()
    handler.proxy()
    os.remove(path)
    assert.is_nil(captured.exit_status)
    assert.are.equal(path, captured.forward_file)
    assert.are.equal("", ngx.var.waf_request_body)
    assert.are.equal("200000", ngx.var.waf_request_body_bytes)
    assert.are.equal("/__waf_stream/standard/ai/knowledge/search", captured.exec_uri)
  end)

  it("applies different contracts to the same path on different hosts", function()
    local config = fixtures.same_path_config()
    init(config, fixtures.routes_for(config))
    local request_a = { host = "service-a.example.internal", method = "POST",
      uri = "/ai/knowledge/search", content_type = "application/json", body_raw = '{"query":"q"}',
      upstream_response = { status = 200, body = '{"results":["one"]}',
        header = { ["Content-Type"] = "application/json" } } }
    set_ngx(request_a)
    handler.access()
    handler.proxy()
    assert.are.equal("service_a_response", ngx.var.waf_response_schema)

    local request_b = { host = "service-b.example.internal", method = "POST",
      uri = "/ai/knowledge/search", content_type = "application/json",
      body_raw = '{"keyword":"k","limit":2}',
      upstream_response = { status = 200,
        body = '{"items":[{"id":1,"title":"one"}],"count":1}',
        header = { ["Content-Type"] = "application/json" } } }
    set_ngx(request_b)
    handler.access()
    handler.proxy()
    assert.are.equal("service_b_response", ngx.var.waf_response_schema)
  end)
end)
