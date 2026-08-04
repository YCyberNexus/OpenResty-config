describe("production nginx V2 templates", function()
  local function read(path)
    local file = assert(io.open(path, "rb"))
    local value = file:read("*a")
    file:close()
    return value
  end

  local function includes(value, fragment)
    return value:find(fragment, 1, true) ~= nil
  end

  it("loads rules, fixed routes, policies, and an explicit node role", function()
    local blue, yellow = read("conf/nginx-blue.conf"), read("conf/nginx-yellow.conf")
    for _, config in ipairs({ blue, yellow }) do
      assert.is_true(includes(config, 'require("waf_rules")'))
      assert.is_true(includes(config, 'require("waf_routes")'))
      assert.is_true(includes(config, 'require("waf_policies")'))
      assert.is_true(includes(config, "include waf-internal-locations.conf;"))
      assert.is_true(includes(config, 'server_name "";'))
      assert.is_true(includes(config, "server_name ~^.+$;"))
    end
    assert.is_true(includes(blue, '"blue")'))
    assert.is_true(includes(yellow, '"yellow")'))
  end)

  it("keeps every next hop fixed in Lua configuration and plain HTTP", function()
    local routes = read("conf/waf_routes.lua")
    assert.is_true(includes(routes, 'address = "10.64.9.2"'))
    assert.is_true(includes(routes, 'address = "192.168.14.249"'))
    assert.is_true(includes(routes, "port = 6789"))
    assert.is_true(includes(routes, 'scheme = "http"'))
    assert.is_nil(routes:find("https", 1, true))
    assert.is_nil(routes:find("$host", 1, true))
  end)

  it("supports prevalidated buffered capture and explicit streaming", function()
    local handler = read("lua/waf/handler.lua")
    local locations = read("conf/waf-internal-locations.conf")
    assert.is_true(includes(handler, "ngx.location.capture"))
    assert.is_true(includes(handler, "ngx.exec"))
    assert.is_true(includes(handler, "validate_response"))
    for _, profile in ipairs({ "fast", "standard", "long" }) do
      assert.is_true(includes(locations, "/__waf_upstream/" .. profile .. "/"))
      assert.is_true(includes(locations, "/__waf_stream/" .. profile .. "/"))
    end
    assert.is_true(includes(locations, "proxy_pass $waf_upstream_origin$waf_upstream_uri;"))
  end)

  it("passes only Lua-sanitized headers and rebuilds protected headers", function()
    local common = read("conf/waf-internal-proxy-common.conf")
    local handler = read("lua/waf/handler.lua")
    assert.is_true(includes(common, "proxy_pass_request_headers on;"))
    assert.is_true(includes(common, "proxy_set_header Host $waf_upstream_host;"))
    assert.is_true(includes(common, 'proxy_set_header Accept-Encoding "";'))
    assert.is_true(includes(common, "proxy_set_header X-WAF-Trace-ID $waf_trace_id;"))
    assert.is_true(includes(handler, "clear_request_headers"))
    assert.is_true(includes(handler, "validated.forward_headers"))
    assert.is_nil(common:find("proxy_set_header Content%-Length"))
  end)

  it("sets bounded buffered and stream request/response limits", function()
    local http = read("conf/waf-http-common.conf")
    local rules = read("conf/waf_rules.lua")
    assert.is_true(includes(http, "client_max_body_size 64m;"))
    assert.is_true(includes(http, "subrequest_output_buffer_size 1m;"))
    assert.is_true(includes(read("conf/nginx-blue.conf"),
      "client_body_temp_path /data/openresty-waf/client_body_temp 1 2;"))
    assert.is_true(includes(read("deploy/openresty-waf@.service"),
      "/data/openresty-waf/client_body_temp"))
    assert.is_true(includes(rules, "max_buffered_response_body_bytes = 1048576"))
    assert.is_true(includes(rules, "max_stream_request_body_bytes = 67108864"))
    assert.is_true(includes(rules, "max_stream_response_body_bytes = 268435456"))
  end)

  it("retains request/response correlation and V2 audit metadata", function()
    local log = read("conf/waf-audit-log-format.conf")
    local common = read("conf/waf-http-common.conf")
    for _, field in ipairs({ "query", "forward_query", "transport", "timeout_profile",
      "forward_header_names", "upstream_origin", "upstream_host", "response_body_sha256" }) do
      assert.is_true(includes(log, '"' .. field .. '"'))
    end
    local blue, yellow = read("conf/nginx-blue.conf"), read("conf/nginx-yellow.conf")
    assert.is_true(includes(blue, "set $waf_trace_id $request_id;"))
    assert.is_true(includes(yellow, "set $waf_trace_id $waf_peer_trace_id;"))
    assert.is_nil(common:find("%$request_body"))
    assert.is_nil(blue:find("ngx.req.read_body", 1, true))
    assert.is_nil(yellow:find("ngx.req.read_body", 1, true))
  end)

  it("packages all V2 runtime and configuration files", function()
    local script = read("scripts/package.sh")
    for _, path in ipairs({ "conf/waf_rules.lua", "conf/waf_routes.lua", "conf/waf_policies.lua",
      "conf/waf-internal-locations.conf", "lua/waf/request_normalizer.lua",
      "lua/waf/policy_engine.lua", "lua/waf/route_table.lua" }) do
      assert.is_true(includes(script, path))
    end
    for _, config in ipairs({ read("conf/nginx-blue.conf"), read("conf/nginx-yellow.conf") }) do
      assert.is_nil(config:find("__[A-Z0-9_]+__"))
    end
  end)
end)
