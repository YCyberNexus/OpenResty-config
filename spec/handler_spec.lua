describe("handler", function()
  local fixtures, json, handler, captured

  local function set_ngx(request)
    request = request or {}
    captured = {
      body = nil, exit_status = nil, forward_body = nil,
      capture_uri = nil, capture_opts = nil,
    }
    local headers = request.headers or {}
    if request.body_raw and request.omit_content_length ~= true and headers["content-length"] == nil then
      headers["content-length"] = tostring(#request.body_raw)
    end
    _G.ngx = {
      status = 200,
      header = {},
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
      },
      print = function(value) captured.body = (captured.body or "") .. tostring(value) end,
      exit = function(status) captured.exit_status = status end,
      sha256_bin = function() return string.rep("\1", 32) end,
      HTTP_GET = 2,
      HTTP_POST = 8,
      HTTP_PUT = 16,
      HTTP_DELETE = 32,
      HTTP_PATCH = 16384,
      location = {
        capture = function(uri, opts)
          captured.capture_uri = uri
          captured.capture_opts = opts
          return request.upstream_response
        end,
      },
      req = {
        get_method = function() return request.method end,
        read_body = function() end,
        get_body_data = function() return request.body_raw end,
        get_body_file = function() return request.body_file end,
        get_headers = function() return headers, request.headers_err end,
        set_body_data = function(value) captured.forward_body = value end,
      },
    }
  end

  local function valid_search_request(overrides)
    local value = {
      host = "127.0.0.1",
      method = "POST",
      uri = "/ai/knowledge/search",
      content_type = "application/json",
      body_raw = json.encode(fixtures.search_request(overrides)),
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
    handler.init(fixtures.config())
  end)

  it("refuses to initialize with an invalid rule file", function()
    local invalid = fixtures.config()
    invalid.whitelist[2].request_schema = "missing"
    assert.is_false(pcall(function() handler.init(invalid) end))
  end)

  it("default-denies an unlisted URL before JSON parsing", function()
    set_ngx({ method = "POST", uri = "/not-listed", content_type = "text/plain", body_raw = "x" })
    handler.access()
    assert.are.equal(403, captured.exit_status)
    assert.are.equal("not_in_whitelist", json.decode(captured.body).error)
    assert.are.equal("x", ngx.var.waf_request_body)
    assert.are.equal(captured.body, ngx.var.waf_forward_response_body)
  end)

  it("default-denies an unlisted host before JSON parsing", function()
    set_ngx({
      host = "other.example.internal", method = "POST", uri = "/ai/knowledge/search",
      content_type = "application/json", body_raw = "{}",
    })
    handler.access()
    assert.are.equal(403, captured.exit_status)
    assert.are.equal("not_in_whitelist", json.decode(captured.body).error)
  end)

  it("rejects query strings, including an empty query component", function()
    set_ngx({ method = "GET", uri = "/ai/knowledge/health", args = "debug=true" })
    handler.access()
    assert.are.equal("query_not_allowed", json.decode(captured.body).error)

    set_ngx({
      method = "GET", uri = "/ai/knowledge/health", args = "", query_present = true,
      force_empty_is_args = true,
    })
    handler.access()
    assert.are.equal("query_not_allowed", json.decode(captured.body).error)
  end)

  it("accepts application/json parameters and rejects other media types", function()
    local accepted = valid_search_request()
    accepted.content_type = "Application/JSON; charset=utf-8"
    set_ngx(accepted)
    handler.access()
    assert.is_nil(captured.exit_status)

    local rejected = valid_search_request()
    rejected.content_type = "application/jsonp"
    set_ngx(rejected)
    handler.access()
    assert.are.equal(415, captured.exit_status)
  end)

  it("rejects invalid, oversized, and disk-buffered request bodies", function()
    local invalid = valid_search_request()
    invalid.body_raw = '{"query":"q"} trailing'
    set_ngx(invalid)
    handler.access()
    assert.are.equal(400, captured.exit_status)

    local oversized = valid_search_request()
    oversized.body_raw = string.rep("x", 16385)
    set_ngx(oversized)
    handler.access()
    assert.are.equal(413, captured.exit_status)

    local buffered = valid_search_request()
    buffered.body_raw = nil
    buffered.body_file = os.tmpname()
    local buffered_file = assert(io.open(buffered.body_file, "wb"))
    buffered_file:write("disk-buffered-body")
    buffered_file:close()
    buffered.headers = { ["content-length"] = "20000" }
    set_ngx(buffered)
    handler.access()
    os.remove(buffered.body_file)
    assert.are.equal(413, captured.exit_status)
    assert.are.equal("disk-buffered-body", ngx.var.waf_request_body)
  end)

  it("allows, normalizes, and records a valid request body", function()
    local request = valid_search_request()
    request.body_raw = '{"query":"first","query":"second","top_k":5}'
    set_ngx(request)
    handler.access()
    assert.is_nil(captured.exit_status)
    assert.are.equal("allow_request", ngx.var.waf_action)
    assert.are.equal("second", json.decode(captured.forward_body).query)
    local _, occurrences = captured.forward_body:gsub('"query"', "")
    assert.are.equal(1, occurrences)
    assert.are.equal(request.body_raw, ngx.var.waf_request_body)
    assert.are.equal(captured.forward_body, ngx.var.waf_forward_body)
    assert.are.equal(64, #ngx.var.waf_request_body_sha256)
    assert.are.equal(64, #ngx.var.waf_forward_body_sha256)
  end)

  it("rejects a body on a bodyless whitelist rule", function()
    set_ngx({
      method = "GET", uri = "/ai/knowledge/health", body_raw = "hidden",
      omit_content_length = true,
    })
    handler.access()
    assert.are.equal(400, captured.exit_status)
    assert.are.equal("unexpected_body", json.decode(captured.body).error)
  end)

  it("captures, validates, normalizes, and audits an allowed response", function()
    local request = valid_search_request()
    request.upstream_response = valid_search_response()
    set_ngx(request)
    handler.access()
    handler.proxy()

    assert.are.equal(200, captured.exit_status)
    assert.are.equal("/__waf_upstream/ai/knowledge/search", captured.capture_uri)
    assert.are.equal(8, captured.capture_opts.method)
    assert.is_nil(captured.capture_opts.copy_all_vars)
    assert.is_nil(captured.capture_opts.share_all_vars)
    assert.are.equal("allow_response", ngx.var.waf_action)
    assert.are.equal("knowledge_search_response", ngx.var.waf_response_schema)
    assert.are.equal("192.0.2.10:6789", ngx.var.waf_upstream_addr)
    assert.are.equal("200", ngx.var.waf_upstream_status)
    assert.are.equal(request.upstream_response.body, ngx.var.waf_response_body)
    assert.are.equal(captured.body, ngx.var.waf_forward_response_body)
    assert.are.equal(64, #ngx.var.waf_response_body_sha256)
    assert.are.equal(64, #ngx.var.waf_forward_response_sha256)
    assert.are.same(fixtures.search_response(), json.decode(captured.body))
  end)

  it("rejects an unlisted status and never exposes the upstream response body", function()
    local request = valid_search_request()
    request.upstream_response = valid_search_response({
      status = 201,
      body = '{"secret":"must-not-leak"}',
    })
    set_ngx(request)
    handler.access()
    handler.proxy()

    assert.are.equal(502, captured.exit_status)
    assert.are.equal("deny_response", ngx.var.waf_action)
    assert.are.equal("response_status_not_allowed", json.decode(captured.body).error)
    assert.are.equal('{"secret":"must-not-leak"}', ngx.var.waf_response_body)
    assert.are.equal(captured.body, ngx.var.waf_forward_response_body)
    assert.is_nil(captured.body:find("must-not-leak", 1, true))
  end)

  it("fails closed when the internal upstream capture raises an error", function()
    local request = valid_search_request()
    set_ngx(request)
    ngx.location.capture = function() error("synthetic capture failure") end
    handler.access()
    handler.proxy()

    assert.are.equal(502, captured.exit_status)
    assert.are.equal("upstream_capture_failed", json.decode(captured.body).error)
    assert.is_nil(captured.body:find("synthetic capture failure", 1, true))
  end)

  it("rejects invalid response media types, JSON, schemas, and encodings", function()
    local cases = {
      {
        response = valid_search_response({ header = { ["Content-Type"] = "text/plain" } }),
        reason = "response_unsupported_media_type",
      },
      {
        response = valid_search_response({ body = "not-json" }),
        reason = "invalid_upstream_json",
      },
      {
        response = valid_search_response({ body = '{"query":"missing fields"}' }),
        reason = "response_body",
      },
      {
        response = valid_search_response({
          header = { ["Content-Type"] = "application/json", ["Content-Encoding"] = "gzip" },
        }),
        reason = "response_content_encoding_not_allowed",
      },
    }
    for _, case in ipairs(cases) do
      local request = valid_search_request()
      request.upstream_response = case.response
      set_ngx(request)
      handler.access()
      handler.proxy()
      assert.are.equal(502, captured.exit_status)
      assert.are.equal(case.reason, json.decode(captured.body).error)
    end
  end)

  it("rejects truncated and per-rule oversized responses", function()
    local request = valid_search_request()
    request.upstream_response = valid_search_response({ truncated = true })
    set_ngx(request)
    handler.access()
    handler.proxy()
    assert.are.equal("response_body_too_large", json.decode(captured.body).error)

    local config = fixtures.config()
    config.whitelist[2].responses[200].max_body_bytes = 10
    handler.init(config)
    request = valid_search_request()
    request.upstream_response = valid_search_response()
    set_ngx(request)
    handler.access()
    handler.proxy()
    assert.are.equal("response_body_too_large", json.decode(captured.body).error)
  end)

  it("applies different request and response schemas to the same path by host", function()
    handler.init(fixtures.same_path_config())

    local request_a = {
      host = "service-a.example.internal", method = "POST", uri = "/ai/knowledge/search",
      content_type = "application/json", body_raw = '{"query":"q"}',
      upstream_response = {
        status = 200, body = '{"results":["one"]}',
        header = { ["Content-Type"] = "application/json" },
      },
    }
    set_ngx(request_a)
    handler.access()
    handler.proxy()
    assert.are.equal(200, captured.exit_status)
    assert.are.equal("service_a_response", ngx.var.waf_response_schema)

    local request_b = {
      host = "service-b.example.internal", method = "POST", uri = "/ai/knowledge/search",
      content_type = "application/json", body_raw = '{"keyword":"k","limit":2}',
      upstream_response = {
        status = 200, body = '{"items":[{"id":1,"title":"one"}],"count":1}',
        header = { ["Content-Type"] = "application/json" },
      },
    }
    set_ngx(request_b)
    handler.access()
    handler.proxy()
    assert.are.equal(200, captured.exit_status)
    assert.are.equal("service_b_response", ngx.var.waf_response_schema)

    request_b.upstream_response.body = '{"results":["wrong contract"]}'
    set_ngx(request_b)
    handler.access()
    handler.proxy()
    assert.are.equal(502, captured.exit_status)
    assert.are.equal("response_body", json.decode(captured.body).error)
  end)
end)
