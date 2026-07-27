describe("handler", function()
  local fixtures, json, handler, captured

  local function upstream(status, body, content_type)
    return {
      status = status,
      body = type(body) == "string" and body or json.encode(body),
      header = { ["Content-Type"] = content_type or "application/json; charset=utf-8" },
    }
  end

  local function set_ngx(request)
    request = request or {}
    captured = { body = nil, exit_status = nil, subrequest = nil, forward_body = nil }
    local headers = request.headers or {}
    if headers.host == nil and request.omit_host ~= true then headers.host = request.host or "localhost" end
    if request.body_raw and request.omit_content_length ~= true and headers["content-length"] == nil then
      headers["content-length"] = tostring(#request.body_raw)
    end
    _G.ngx = {
      INFO = "info",
      HTTP_GET = 0,
      HTTP_POST = 1,
      HTTP_PUT = 2,
      HTTP_PATCH = 3,
      HTTP_DELETE = 4,
      status = 200,
      header = {},
      ctx = {},
      var = {
        uri = request.uri,
        request_uri = request.request_uri or (request.uri
          .. ((request.query_present or request.args ~= nil) and "?" or "")
          .. (request.args or "")),
        host = request.host or "localhost",
        args = request.args,
        is_args = request.force_empty_is_args and ""
          or (request.query_present and "?" or (request.args ~= nil and "?" or "")),
        content_type = request.content_type,
        request_id = "local-rid-1",
        waf_trace_id = "trace-rid-1",
      },
      log = function() end,
      print = function(value) captured.body = (captured.body or "") .. tostring(value) end,
      exit = function(status) captured.exit_status = status end,
      sha256_bin = function() return string.rep("\1", 32) end,
      req = {
        get_method = function() return request.method end,
        read_body = function() end,
        get_body_data = function() return request.body_raw end,
        get_body_file = function() return request.body_file end,
        get_headers = function() return headers, request.headers_err end,
        set_body_data = function(value) captured.forward_body = value end,
      },
      re = {
        find = function(value, pattern) return string.find(value, pattern) end,
      },
      location = {
        capture = function(uri, opts)
          captured.subrequest = { uri = uri, opts = opts }
          return request.upstream_response
        end,
      },
    }
  end

  local function valid_search_request(overrides)
    local request_body = fixtures.search_request(overrides)
    return {
      method = "POST",
      uri = "/ai/knowledge/search",
      content_type = "application/json",
      body_raw = json.encode(request_body),
      upstream_response = upstream(200, fixtures.search_response(overrides)),
    }
  end

  before_each(function()
    fixtures = require("spec.fixtures")
    json = fixtures.json
    package.preload["cjson.safe"] = function() return json end
    package.loaded["cjson.safe"] = nil
    package.loaded["waf.handler"] = nil
    handler = require("waf.handler")
    handler.init(fixtures.config(), { allowed_hosts = { "localhost" } })
  end)

  it("refuses to initialize with an invalid operations rule file", function()
    local invalid = fixtures.config()
    invalid.whitelist[1].response_schemas = nil
    local ok = pcall(function()
      handler.init(invalid, { allowed_hosts = { "localhost" } })
    end)
    assert.is_false(ok)
  end)

  it("refuses example rules when initialized in production mode", function()
    local ok = pcall(function()
      handler.init(fixtures.config(), { allowed_hosts = { "localhost" }, production = true })
    end)
    assert.is_false(ok)
  end)

  it("default-denies an unlisted URL before attempting JSON parsing", function()
    set_ngx({ method = "POST", uri = "/ai/knowledge/export", content_type = "text/plain", body_raw = "x" })
    handler.access()
    assert.are.equal(403, captured.exit_status)
    assert.are.equal("not_in_whitelist", json.decode(captured.body).error)
  end)

  it("rejects an unregistered Host", function()
    set_ngx({ method = "GET", uri = "/ai/knowledge/health", host = "other.internal" })
    handler.access()
    assert.are.equal(403, captured.exit_status)
    assert.are.equal("host_not_allowed", json.decode(captured.body).error)
  end)

  it("rejects a request that omits Host instead of accepting nginx server_name fallback", function()
    set_ngx({ method = "GET", uri = "/ai/knowledge/health", omit_host = true })
    handler.access()
    assert.are.equal(403, captured.exit_status)
    assert.are.equal("host_not_allowed", json.decode(captured.body).error)
  end)

  it("rejects query strings on both knowledge URLs", function()
    set_ngx({ method = "GET", uri = "/ai/knowledge/health", args = "debug=true" })
    handler.access()
    assert.are.equal(403, captured.exit_status)
    assert.are.equal("query_not_allowed", json.decode(captured.body).error)
  end)

  it("rejects even an empty query component", function()
    set_ngx({
      method = "GET", uri = "/ai/knowledge/health", args = "", query_present = true,
      force_empty_is_args = true,
    })
    handler.access()
    assert.are.equal(403, captured.exit_status)
    assert.are.equal("query_not_allowed", json.decode(captured.body).error)
  end)

  it("accepts application/json parameters but rejects other media types", function()
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

  it("rejects invalid JSON and trailing data", function()
    local request = valid_search_request()
    request.body_raw = '{"query":"q"} trailing'
    set_ngx(request)
    handler.access()
    assert.are.equal(400, captured.exit_status)
    assert.are.equal("invalid_json", json.decode(captured.body).error)
  end)

  it("rejects a request body that spills to disk", function()
    local request = valid_search_request()
    request.body_raw = nil
    request.body_file = "/tmp/client-body"
    set_ngx(request)
    handler.access()
    assert.are.equal(413, captured.exit_status)
  end)

  it("allows a valid request and records only its size and digest in audit variables", function()
    local request = valid_search_request()
    set_ngx(request)
    handler.access()
    assert.is_nil(captured.exit_status)
    assert.are.equal("allow_request", ngx.var.waf_action)
    assert.are.equal(tostring(#request.body_raw), ngx.var.waf_request_body_bytes)
    assert.are.equal(64, #ngx.var.waf_request_body_sha256)
    assert.are.equal(tostring(#captured.forward_body), ngx.var.waf_forward_body_bytes)
    assert.are.equal(64, #ngx.var.waf_forward_body_sha256)
    assert.are.equal("application/json", ngx.var.waf_upstream_content_type)
  end)

  it("normalizes validated JSON before forwarding to remove duplicate-key ambiguity", function()
    local request = valid_search_request()
    request.body_raw = '{"query":"first","query":"second","top_k":5}'
    set_ngx(request)
    handler.access()
    assert.is_nil(captured.exit_status)
    assert.are.equal("second", json.decode(captured.forward_body).query)
    local _, occurrences = captured.forward_body:gsub('"query"', "")
    assert.are.equal(1, occurrences)
  end)

  it("proxies with the original method/path and returns a validated response", function()
    local request = valid_search_request()
    set_ngx(request)
    handler.access()
    handler.proxy()
    assert.are.equal("/_waf_upstream/ai/knowledge/search", captured.subrequest.uri)
    assert.are.equal(ngx.HTTP_POST, captured.subrequest.opts.method)
    assert.is_true(captured.subrequest.opts.always_forward_body)
    assert.is_true(captured.subrequest.opts.copy_all_vars)
    assert.are.equal(200, ngx.status)
    assert.are.equal("allow_response", ngx.var.waf_action)
    assert.are.equal(fixtures.search_response().query, json.decode(captured.body).query)
  end)

  it("validates the health response without forwarding a request body", function()
    set_ngx({
      method = "GET",
      uri = "/ai/knowledge/health",
      upstream_response = upstream(200, fixtures.health_response()),
    })
    handler.access()
    handler.proxy()
    assert.is_false(captured.subrequest.opts.always_forward_body)
    assert.are.equal("", ngx.var.waf_upstream_content_type)
    assert.are.equal("allow_response", ngx.var.waf_action)
  end)

  it("rejects a bodyless URL body even when no body length header is present", function()
    set_ngx({
      method = "GET",
      uri = "/ai/knowledge/health",
      body_raw = "hidden-body",
      omit_content_length = true,
    })
    handler.access()
    assert.are.equal(400, captured.exit_status)
    assert.are.equal("unexpected_body", json.decode(captured.body).error)
    assert.are.equal(tostring(#"hidden-body"), ngx.var.waf_request_body_bytes)
  end)

  it("replaces a malformed upstream body with a generic 502 and does not leak it", function()
    local request = valid_search_request()
    request.upstream_response = upstream(200, '{"secret":"yellow-data"}')
    set_ngx(request)
    handler.access()
    handler.proxy()
    assert.are.equal(502, captured.exit_status)
    assert.are.equal("deny_response", ngx.var.waf_action)
    assert.is_nil(captured.body:find("yellow-data", 1, true))
    assert.are.equal("Upstream response rejected", json.decode(captured.body).detail)
  end)

  it("rejects an unregistered upstream status even if its JSON is well formed", function()
    local request = valid_search_request()
    request.upstream_response = upstream(500, { detail = "internal failure" })
    set_ngx(request)
    handler.access()
    handler.proxy()
    assert.are.equal(502, captured.exit_status)
    assert.are.equal("response_status_not_allowed", ngx.var.waf_reason)
  end)

  it("rejects a non-JSON upstream response", function()
    local request = valid_search_request()
    request.upstream_response = upstream(200, "<html>failure</html>", "text/html")
    set_ngx(request)
    handler.access()
    handler.proxy()
    assert.are.equal(502, captured.exit_status)
    assert.are.equal("response_media_type", ngx.var.waf_reason)
  end)

  it("rejects ambiguous duplicate upstream Content-Type headers", function()
    local request = valid_search_request()
    request.upstream_response.header["Content-Type"] = { "application/json", "text/plain" }
    set_ngx(request)
    handler.access()
    handler.proxy()
    assert.are.equal(502, captured.exit_status)
    assert.are.equal("response_media_type", ngx.var.waf_reason)
  end)

  it("normalizes a validated response before returning it to the caller", function()
    local request = valid_search_request()
    request.upstream_response = upstream(200,
      '{"query":"first","query":"second","top_k":5,'
      .. '"retrieval_mode":"pgvector_active_versions_only",'
      .. '"embedding_model":"BAAI/bge-base-zh-v1.5","results":[]}')
    set_ngx(request)
    handler.access()
    handler.proxy()
    assert.are.equal("second", json.decode(captured.body).query)
    local _, occurrences = captured.body:gsub('"query"', "")
    assert.are.equal(1, occurrences)
    assert.are.equal(tostring(#captured.body), ngx.var.waf_response_body_bytes)
  end)
end)
