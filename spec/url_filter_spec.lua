describe("url_filter", function()
  local UrlFilter

  before_each(function()
    package.loaded["waf.url_filter"] = nil
    UrlFilter = require("waf.url_filter")
  end)

  it("matches only an exact path with an allowed method", function()
    local filter = UrlFilter.new({
      { methods = { "POST" }, path = "/ai/knowledge/search" },
    })
    assert.is_not_nil(filter:match("POST", "/ai/knowledge/search"))
    assert.is_nil(filter:match("GET", "/ai/knowledge/search"))
    assert.is_nil(filter:match("POST", "/ai/knowledge/search/extra"))
  end)

  it("does not treat regex-looking paths specially", function()
    local filter = UrlFilter.new({
      { methods = { "GET" }, path = "^/admin/.*$" },
    })
    assert.is_nil(filter:match("GET", "/admin/users"))
  end)
end)
