-- V2 固定路由台账。接口规则只描述 HTTP 契约；这里描述每个 WAF 节点到下一跳的固定地址。
-- address 只接受 IPv4，不能从请求参数、Host 或环境变量动态拼接，避免形成开放代理/SSRF。
return {
  version = 2,
  required_node_roles = { "blue", "yellow" },

  nodes = {
    blue = {
      ["kb.pxsemic.tech"] = {
        scheme = "http",
        address = "10.64.9.2",
        port = 80,
        upstream_host = "kb.pxsemic.tech",
        timeout_profile = "standard",
      },
      ["kb-1.pxsemic.tech"] = {
        scheme = "http",
        address = "10.64.9.2",
        port = 80,
        upstream_host = "kb-1.pxsemic.tech",
        timeout_profile = "standard",
      },
    },

    yellow = {
      ["kb.pxsemic.tech"] = {
        scheme = "http",
        address = "192.168.14.249",
        port = 6789,
        upstream_host = "kb.pxsemic.tech",
        timeout_profile = "standard",
      },
      ["kb-1.pxsemic.tech"] = {
        scheme = "http",
        address = "192.168.14.249",
        port = 6789,
        -- kb-1 是入口别名；现场后端统一要求主 Host。
        upstream_host = "kb.pxsemic.tech",
        timeout_profile = "standard",
      },
    },

    -- 仅供 conf/nginx.conf 本地联调，不参与生产链路。
    dev = {
      ["127.0.0.1"] = {
        scheme = "http",
        address = "127.0.0.1",
        port = 18080,
        upstream_host = "knowledge-stub.local",
        timeout_profile = "standard",
      },
      ["service-a.example.internal"] = {
        scheme = "http",
        address = "127.0.0.1",
        port = 18080,
        upstream_host = "knowledge-stub.local",
        timeout_profile = "standard",
      },
      ["service-b.example.internal"] = {
        scheme = "http",
        address = "127.0.0.1",
        port = 18080,
        upstream_host = "knowledge-stub.local",
        timeout_profile = "standard",
      },
    },
  },
}
