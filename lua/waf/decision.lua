-- 决策链：先黑后白 + 默认拒绝（fail-closed）。
-- 组合 url_filter（黑/白名单）与 body_validator，给出最终放行/拒绝判定。
-- 纯逻辑，不依赖 ngx。
-- evaluate(req{method, path, body}) -> { action="allow"|"deny", status, reason, ... }
local Decision = {}
Decision.__index = Decision

function Decision.new(opts)
  opts = opts or {}
  -- 预处理禁用头规则：统一小写；末尾 * 视为前缀匹配（拦整族，如 x-openclaw-*）。
  -- ngx.req.get_headers() 返回的 key 已是小写，配置里大写在此被规范化掉（故大写配置仍能命中）。
  local forbidden = {}
  for _, h in ipairs(opts.forbidden_headers or {}) do
    local name = tostring(h):lower()
    if name:sub(-1) == "*" then
      local p = name:sub(1, -2)
      -- 跳过空前缀（裸 "*"）：它会匹配所有头、拦死全部请求；正常应被 rules_lint 拦在配置阶段
      if p ~= "" then
        forbidden[#forbidden + 1] = { prefix = p }
      end
    elseif name ~= "" then
      forbidden[#forbidden + 1] = { exact = name }
    end
  end
  return setmetatable({
    whitelist = opts.whitelist,
    blacklist = opts.blacklist,
    validators = opts.validators or {},
    forbidden_headers = forbidden,
  }, Decision)
end

local function deny(status, reason, extra)
  local r = { action = "deny", status = status, reason = reason }
  if extra then
    for k, v in pairs(extra) do r[k] = v end
  end
  return r
end

-- 把进入的 header key 规范化：小写 + 下划线视作连字符
-- （防 underscores_in_headers on 时 x_openclaw_model 这类形态绕过禁用头）。
local function norm_header(k)
  return tostring(k):lower():gsub("_", "-")
end

function Decision:evaluate(req)
  -- ① 禁用请求头：拦 x-openclaw-* 等能旁路 model 白名单的“后端覆盖头”，全局硬拒，先于一切
  if #self.forbidden_headers > 0 then
    -- 头被截断（条数超过 get_headers 上限）时无法完整核验，fail-closed 直接拒，不基于残缺表放行
    if req.headers_truncated then
      return deny(400, "too_many_headers")
    end
    local headers = req.headers
    if headers then
      for k in pairs(headers) do
        local nk = norm_header(k)
        for _, f in ipairs(self.forbidden_headers) do
          if (f.exact and nk == f.exact)
            or (f.prefix and nk:sub(1, #f.prefix) == f.prefix) then
            return deny(403, "forbidden_header", { field = nk })
          end
        end
      end
    end
  end

  -- ② 先过黑名单：命中即拒，避免白名单 URL 上夹带攻击 payload 被放行
  if self.blacklist and self.blacklist:match(req.method, req.path) then
    return deny(403, "blacklist")
  end

  -- ③ 再过白名单：未命中一律拒绝（默认拒绝 / fail-closed）
  local rule = self.whitelist:match(req.method, req.path)
  if not rule then
    return deny(403, "not_in_whitelist")
  end

  -- ④ 命中规则若声明了 body schema，则做 body 校验
  if rule.body then
    local validator = self.validators[rule.body]
    if not validator then
      return deny(500, "misconfigured", { field = rule.body })
    end
    local ok, err = validator:validate(req.body)
    if not ok then
      local status = (err.code == "schema") and 400 or 422
      return deny(status, "body", { field = err.field, message = err.message })
    end
  end

  return { action = "allow", status = 200, rule = rule }
end

return Decision
