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

  it("matches typed named parameters in any path segment", function()
    local filter = UrlFilter.new({
      {
        id = "ASSET",
        host = "service.example.internal",
        methods = { "GET" },
        path_template = "/tenants/{tenant_id}/assets/{asset_id}",
        path_parameters = {
          tenant_id = { type = "string", format = "slug" },
          asset_id = { type = "string", format = "uuid" },
        },
      },
    })
    local path = "/tenants/team-a/assets/f440c18e-a281-44bc-a878-8aa92b620879"
    local rule, params = filter:match("service.example.internal", "GET", path)
    assert.are.equal("ASSET", rule.id)
    assert.are.equal("team-a", params.tenant_id)
    assert.are.equal("f440c18e-a281-44bc-a878-8aa92b620879", params.asset_id)
    assert.is_nil(filter:match("service.example.internal", "GET",
      "/tenants/team-a/assets/not-a-uuid"))
    assert.is_nil(filter:match("service.example.internal", "GET", path .. "/extra"))
    assert.is_nil(filter:match("service.example.internal", "POST", path))
  end)

  it("detects overlap between an exact UUID route and its template", function()
    local exact = {
      path = "/ai/knowledge/assets/f440c18e-a281-44bc-a878-8aa92b620879",
    }
    local template = {
      path_template = "/ai/knowledge/assets/{asset_id}",
      path_parameters = { asset_id = { type = "string", format = "uuid" } },
    }
    assert.is_true(UrlFilter.paths_overlap(exact, template))
    assert.is_false(UrlFilter.paths_overlap(
      { path = "/ai/knowledge/assets/not-a-uuid" }, template))
  end)

  it("does not treat regex-looking paths specially", function()
    local filter = UrlFilter.new({
      { host = "service.example.internal", methods = { "GET" }, path = "^/admin/.*$" },
    })
    assert.is_nil(filter:match("service.example.internal", "GET", "/admin/users"))
  end)
end)
