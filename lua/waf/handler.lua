-- access_by_lua 入口：连接 ngx 运行时与纯逻辑决策器。
-- 职责仅限 IO 胶水：取 method/uri、读并解析 body、调 decision、回写响应与日志。
-- 所有规则逻辑都在可单测的 waf.* 纯模块里，这里不做规则判断。
local cjson = require("cjson.safe")
local factory = require("waf.factory")
local regex = require("waf.regex")

local _M = {}

local decision  -- init 阶段构建一次，access 阶段复用

function _M.init(config)
  decision = factory.build_decision(config, regex.match)
end

local function respond(status, payload)
  ngx.status = status
  ngx.header.content_type = "application/json"
  ngx.say(cjson.encode(payload))
  return ngx.exit(status)
end

local function has_body(method)
  return method == "POST" or method == "PUT" or method == "PATCH"
end

function _M.access()
  local method = ngx.req.get_method()
  local path = ngx.var.uri
  local request_id = ngx.var.request_id
  local body

  if has_body(method) then
    local ctype = ngx.var.content_type or ""
    -- 强制 application/json，避免 text/plain、multipart 夹带绕过校验（方案 P3-1）
    if not ctype:find("application/json", 1, true) then
      return respond(415, { error = "unsupported_media_type", request_id = request_id })
    end
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    -- raw == nil 可能是空 body，也可能是 body 落盘（须把 client_body_buffer_size
    -- 调到与 client_max_body_size 一致来规避，见方案 P3-1）。起步骨架按空 body 处理。
    if raw ~= nil then
      local parsed = cjson.decode(raw)
      if parsed == nil then
        return respond(400, { error = "invalid_json", request_id = request_id })
      end
      body = parsed
    end
  end

  local r = decision:evaluate({ method = method, path = path, body = body })

  ngx.log(ngx.INFO, "waf action=", r.action,
    " method=", method, " path=", path,
    " reason=", r.reason or "-", " field=", r.field or "-")

  if r.action == "deny" then
    -- 对外只回原因码与 request_id，不回显具体规则/原始内容（防探测绕过，方案 P3-7）
    return respond(r.status, { error = r.reason, field = r.field, request_id = request_id })
  end
  -- allow：交给后续 content/proxy_pass 阶段放行到对端 OpenClaw
end

return _M
