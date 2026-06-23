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
  local headers, headers_err = ngx.req.get_headers()  -- 第二返回值 "truncated" 表示头条数超上限被截断
  local body

  if has_body(method) then
    local ctype = ngx.var.content_type or ""
    -- 强制 application/json，避免 text/plain、multipart 夹带绕过校验（方案 P3-1）
    if not ctype:find("application/json", 1, true) then
      return respond(415, { error = "unsupported_media_type", request_id = request_id })
    end
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if raw == nil then
      -- raw==nil 有两种：真空 body，或 body 落盘（超过 client_body_buffer_size）。
      -- 落盘时内存里读不到内容、无法校验——必须拒绝，绝不当空 body 放行（fail-closed，方案 P3-1）。
      if ngx.req.get_body_file() ~= nil then
        return respond(413, { error = "body_too_large", request_id = request_id })
      end
      -- 否则为真正的空 body，body 保持 nil 交给后续规则判定。
    else
      local parsed = cjson.decode(raw)
      if parsed == nil then
        return respond(400, { error = "invalid_json", request_id = request_id })
      end
      body = parsed
    end
  end

  local r = decision:evaluate({
    method = method, path = path, body = body,
    headers = headers, headers_truncated = (headers_err == "truncated"),
  })

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
