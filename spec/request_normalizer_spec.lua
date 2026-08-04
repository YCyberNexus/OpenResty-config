describe("request_normalizer", function()
  local normalizer

  before_each(function()
    package.loaded["waf.request_normalizer"] = nil
    normalizer = require("waf.request_normalizer")
  end)

  local query_schema = {
    type = "object", additional_properties = false,
    properties = {
      q = { type = "string" }, page = { type = "integer" },
      score = { type = "number" }, enabled = { type = "boolean" },
      tag = { type = "array", items = { type = "string" }, max_items = 3 },
    },
  }

  it("strictly decodes, types, and canonically encodes Query", function()
    local value, encoded = normalizer.parse_query(
      "tag=b&q=%E4%B8%AD%E6%96%87&page=02&enabled=false&score=1.50&tag=a",
      query_schema, 8192, 64)
    assert.are.equal("中文", value.q)
    assert.are.equal(2, value.page)
    assert.are.equal(false, value.enabled)
    assert.are.equal(1.5, value.score)
    assert.are.same({ "b", "a" }, value.tag)
    assert.are.equal("enabled=false&page=2&q=%E4%B8%AD%E6%96%87&score=1.5&tag=b&tag=a", encoded)
  end)

  it("rejects malformed escapes, controls, duplicate scalars and too many pairs", function()
    local cases = {
      { "q=%GG", "invalid_query" },
      { "q=%00", "invalid_query" },
      { "page=1&page=2", "duplicate_query_parameter" },
      { "page=one", "query_type" },
      { "q=a&&page=1", "invalid_query" },
    }
    for _, case in ipairs(cases) do
      local value, err = normalizer.parse_query(case[1], query_schema, 8192, 64)
      assert.is_nil(value)
      assert.are.equal(case[2], err.reason)
    end
    local value, err = normalizer.parse_query("q=a&page=1", query_schema, 8192, 1)
    assert.is_nil(value)
    assert.are.equal("too_many_query_parameters", err.reason)
  end)

  it("normalizes header names and catches case/underscore collisions", function()
    local headers, err = normalizer.normalize_headers({ ["X-Tenant-ID"] = "one", x_tenant_id = "two" })
    assert.is_nil(headers)
    assert.are.equal("duplicate_header", err.reason)
    headers = assert(normalizer.normalize_headers({ ["X-Tenant-ID"] = "one" }))
    assert.are.equal("one", headers["x-tenant-id"])
  end)

  it("recognizes only well-formed exact media types", function()
    assert.are.equal("application/json", normalizer.media_type(" Application/JSON; charset=utf-8"))
    assert.is_true(normalizer.media_type_allowed("application/pdf", { "application/pdf" }))
    assert.is_false(normalizer.media_type_allowed("application/jsonp", { "application/json" }))
    assert.is_nil(normalizer.media_type("text/plain\r\nx-evil: yes"))
  end)
end)
