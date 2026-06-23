-- 把生产 conf/waf_rules.lua 纳入 make test：加载真实规则、跑配置体检、断言关键安全策略在位。
-- 消除“内联测试 config 全绿但生产规则可能配错/漏配”的盲区（check_rules.lua 只在手动 lint 时跑）。
describe("conf/waf_rules.lua (production config)", function()
  local lint, config

  before_each(function()
    package.loaded["waf.rules_lint"] = nil
    lint = require("waf.rules_lint")
    -- make test 从仓库根目录运行（luajit spec/run.lua），相对路径可直达 conf/。
    local chunk = assert(loadfile("conf/waf_rules.lua"))
    config = chunk()
  end)

  it("loads and passes rules_lint with zero errors", function()
    local issues = lint.lint(config)
    assert.are.equal(0, lint.count(issues, "error"))
  end)

  it("blocks the x-openclaw-* override-header family (model allowlist guard in place)", function()
    local found = false
    for _, h in ipairs(config.forbidden_headers or {}) do
      if h == "x-openclaw-*" then found = true end
    end
    assert.is_true(found)
  end)

  it("keeps every forbidden_headers entry lowercase", function()
    for _, h in ipairs(config.forbidden_headers or {}) do
      assert.are.equal(string.lower(h), h)
    end
  end)

  it("default-denies: has a non-empty whitelist and the chat schema it references", function()
    assert.truthy(config.whitelist and #config.whitelist > 0)
    assert.is_not_nil(config.schemas and config.schemas.chat)
  end)
end)
