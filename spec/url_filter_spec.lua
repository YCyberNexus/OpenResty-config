describe("url_filter", function()
  local UrlFilter

  before_each(function()
    package.loaded["waf.url_filter"] = nil
    UrlFilter = require("waf.url_filter")
  end)

  it("matches only an exact host, path, and allowed method", function()
    local filter = UrlFilter.new({
      { host = "service-a.example.internal", methods = { "POST" }, path = "/ai/knowledge/search" },
    })
    assert.is_not_nil(filter:match("service-a.example.internal", "POST", "/ai/knowledge/search"))
    assert.is_nil(filter:match("service-b.example.internal", "POST", "/ai/knowledge/search"))
    assert.is_nil(filter:match("service-a.example.internal", "GET", "/ai/knowledge/search"))
    assert.is_nil(filter:match("service-a.example.internal", "POST", "/ai/knowledge/search/extra"))
  end)

  it("distinguishes two services with the same method and path", function()
    local a = { id = "A", host = "service-a.example.internal", methods = { "POST" }, path = "/same" }
    local b = { id = "B", host = "service-b.example.internal", methods = { "POST" }, path = "/same" }
    local filter = UrlFilter.new({ a, b })
    assert.are.equal("A", filter:match(a.host, "POST", "/same").id)
    assert.are.equal("B", filter:match(b.host, "POST", "/same").id)
  end)

  it("does not treat regex-looking paths specially", function()
    local filter = UrlFilter.new({
      { host = "service.example.internal", methods = { "GET" }, path = "^/admin/.*$" },
    })
    assert.is_nil(filter:match("service.example.internal", "GET", "/admin/users"))
  end)
end)
