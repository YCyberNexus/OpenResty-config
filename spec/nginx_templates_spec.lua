describe("production nginx templates", function()
  local function read(path)
    local file = assert(io.open(path, "rb"))
    local value = file:read("*a")
    file:close()
    return value
  end

  local function includes(value, fragment)
    return value:find(fragment, 1, true) ~= nil
  end

  it("uses plain HTTP between the L4-restricted blue and yellow nodes", function()
    local blue = read("conf/nginx-blue.conf.template")
    local yellow = read("conf/nginx-yellow.conf.template")
    assert.is_true(includes(blue, "proxy_pass http://yellow_waf;"))
    assert.is_true(includes(yellow, "proxy_pass http://protected_backend;"))
    for _, config in ipairs({ blue, yellow }) do
      assert.is_nil(config:lower():find("mtls", 1, true))
      assert.is_nil(config:find("ssl_", 1, true))
      assert.is_nil(config:find("certificate", 1, true))
    end
  end)

  it("runs request filtering before direct proxying and does not capture responses", function()
    local public = read("conf/waf-public-location.conf")
    local handler = read("lua/waf/handler.lua")
    assert.is_true(includes(public, 'require("waf.handler").access()'))
    assert.is_nil(public:find("content_by_lua", 1, true))
    assert.is_nil(handler:find("ngx.location.capture", 1, true))
    assert.is_nil(handler:find("validate_response", 1, true))
  end)

  it("rebuilds forwarded request headers and keeps local audit records", function()
    local blue = read("conf/nginx-blue.conf.template")
    local yellow = read("conf/nginx-yellow.conf.template")
    local log_format = read("conf/waf-audit-log-format.conf")
    for _, config in ipairs({ blue, yellow }) do
      assert.is_true(includes(config, 'local rules = require("waf_rules")'))
      assert.is_true(includes(config, "proxy_pass_request_headers off;"))
      assert.is_true(includes(config, "proxy_set_header Content-Type $waf_upstream_content_type;"))
      assert.is_true(includes(config, "proxy_set_header Content-Length $waf_forward_body_bytes;"))
      assert.is_true(includes(config, "/data/openresty-waf/audit/access.log waf_audit;"))
      assert.is_true(includes(config, "/data/openresty-waf/audit/rejected.log waf_reject;"))
      assert.is_true(includes(config, "proxy_buffering off;"))
    end
    assert.is_nil(log_format:find("peer_mtls", 1, true))
    assert.is_nil(log_format:find("response_body", 1, true))
    assert.is_true(includes(log_format, '"upstream_status":"$upstream_status"'))
  end)
end)
