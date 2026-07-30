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
    assert.is_true(includes(yellow, "proxy_pass http://protected_backend_a;"))
    assert.is_true(includes(yellow, "proxy_pass http://protected_backend_b;"))
    for _, config in ipairs({ blue, yellow }) do
      assert.is_nil(config:lower():find("mtls", 1, true))
      assert.is_nil(config:find("ssl_", 1, true))
      assert.is_nil(config:find("certificate", 1, true))
    end
  end)

  it("captures upstream responses before validating and returning them", function()
    local public = read("conf/waf-public-location.conf")
    local handler = read("lua/waf/handler.lua")
    assert.is_true(includes(public, 'require("waf.handler").access()'))
    assert.is_true(includes(public, 'require("waf.handler").proxy()'))
    assert.is_true(includes(handler, "ngx.location.capture"))
    assert.is_true(includes(handler, "validate_response"))
    local common = read("conf/waf-http-common.conf")
    assert.is_true(includes(common, "subrequest_output_buffer_size 1m;"))
  end)

  it("rebuilds forwarded request headers and keeps local audit records", function()
    local blue = read("conf/nginx-blue.conf.template")
    local yellow = read("conf/nginx-yellow.conf.template")
    local proxy_common = read("conf/waf-internal-proxy-common.conf")
    local log_format = read("conf/waf-audit-log-format.conf")
    for _, config in ipairs({ blue, yellow }) do
      assert.is_true(includes(config, 'local rules = require("waf_rules")'))
      assert.is_true(includes(config, "location ^~ /__waf_upstream/"))
      assert.is_true(includes(config, "internal;"))
      assert.is_true(includes(config, "include waf-internal-proxy-common.conf;"))
      assert.is_true(includes(config, "/data/openresty-waf/audit/access.log waf_audit;"))
      assert.is_true(includes(config, "/data/openresty-waf/audit/rejected.log waf_reject;"))
    end
    assert.is_true(includes(proxy_common, "proxy_pass_request_headers off;"))
    assert.is_true(includes(proxy_common, "proxy_set_header Content-Type application/json;"))
    assert.is_nil(proxy_common:find("proxy_set_header Content%-Length"))
    assert.is_true(includes(proxy_common, "proxy_set_header Accept-Encoding \"\";"))
    assert.is_nil(log_format:find("peer_mtls", 1, true))
    assert.is_true(includes(log_format, '"response_body_sha256":"$waf_response_body_sha256"'))
    assert.is_true(includes(log_format, '"upstream_status":"$waf_upstream_status"'))
  end)

  it("preserves an approved service host across blue and routes two yellow backends", function()
    local blue = read("conf/nginx-blue.conf.template")
    local yellow = read("conf/nginx-yellow.conf.template")
    assert.is_true(includes(blue, "server_name __WAF_SERVICE_HOST_A__ __WAF_SERVICE_HOST_B__;"))
    assert.is_true(includes(blue, "proxy_set_header Host $host;"))
    assert.is_true(includes(yellow, "server_name __WAF_SERVICE_HOST_A__;"))
    assert.is_true(includes(yellow, "server_name __WAF_SERVICE_HOST_B__;"))
  end)
end)
