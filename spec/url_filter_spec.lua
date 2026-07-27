describe("url_filter", function()
  local UrlFilter

  before_each(function()
    package.loaded["waf.url_filter"] = nil
    UrlFilter = require("waf.url_filter")
  end)

  it("matches an exact path when the method is allowed", function()
    local f = UrlFilter.new({
      { methods = { "POST" }, path = "/ai/knowledge/search" },
    })
    assert.is_not_nil(f:match("POST", "/ai/knowledge/search"))
  end)

  it("does not match when the method is not allowed", function()
    local f = UrlFilter.new({
      { methods = { "POST" }, path = "/ai/knowledge/search" },
    })
    assert.is_nil(f:match("GET", "/ai/knowledge/search"))
  end)

  it("matches a regex rule via the injected regex engine", function()
    local seen = {}
    local regex_match = function(pattern, str)
      seen.pattern, seen.str = pattern, str
      return true
    end
    local f = UrlFilter.new({
      { methods = { "POST" }, pattern = "^/v1/.*$" },
    }, regex_match)
    assert.is_not_nil(f:match("POST", "/ai/knowledge/search"))
    assert.are.equal("^/v1/.*$", seen.pattern)
    assert.are.equal("/ai/knowledge/search", seen.str)
  end)

  it("does not match a regex rule when the engine returns false", function()
    local f = UrlFilter.new({
      { methods = { "POST" }, pattern = "^/admin/.*$" },
    }, function() return false end)
    assert.is_nil(f:match("POST", "/ai/knowledge/search"))
  end)
end)
