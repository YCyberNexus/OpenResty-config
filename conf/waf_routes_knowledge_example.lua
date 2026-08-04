-- 仅用于 conf/nginx.conf 本地联调。
return {
  version = 2,
  required_node_roles = { "dev" },
  nodes = {
    dev = {
      ["127.0.0.1"] = {
        scheme = "http",
        address = "127.0.0.1",
        port = 18080,
        upstream_host = "knowledge-stub.local",
        timeout_profile = "standard",
      },
    },
  },
}
