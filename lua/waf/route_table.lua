-- 将已通过静态体检的 Host 映射到当前节点的固定下一跳。
local RouteTable = {}
RouteTable.__index = RouteTable

function RouteTable.new(config, node_role)
  config = config or {}
  return setmetatable({
    node_role = node_role,
    routes = type(config.nodes) == "table" and config.nodes[node_role] or nil,
  }, RouteTable)
end

function RouteTable:resolve(host)
  local route = self.routes and self.routes[host]
  if not route then return nil end
  return {
    scheme = route.scheme,
    address = route.address,
    port = route.port,
    upstream_host = route.upstream_host,
    timeout_profile = route.timeout_profile,
    origin = string.format("%s://%s:%d", route.scheme, route.address, route.port),
  }
end

return RouteTable
