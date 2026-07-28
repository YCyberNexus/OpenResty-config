describe("handler", function()
  local fixtures, json, handler, captured

  local function set_ngx(request)
    request = request or {}
    captured = { body = nil, exit_status = nil, forward_body = nil }
    local headers = request.headers or {}
    if request.body_raw and request.omit_content_length ~= true and headers["content-length"] == nil then
      headers["content-length"] = tostring(#request.body_raw)
    end
    _G.ngx = {
      status = 200,
      header = {},
      var = {
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
    return {
      method = "POST",
      uri = "/ai/knowledge/search",
      content_type = "application/json",
      body_raw = json.encode(fixtures.search_request(overrides)),
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
    buffered.body_file = "/tmp/client-body"
    buffered.headers = { ["content-length"] = "20000" }
    set_ngx(buffered)
    handler.access()
    assert.are.equal(413, captured.exit_status)
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
    assert.are.equal(64, #ngx.var.waf_request_body_sha256)
    assert.are.equal(64, #ngx.var.waf_forward_body_sha256)
    assert.are.equal("application/json", ngx.var.waf_upstream_content_type)
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
end)
