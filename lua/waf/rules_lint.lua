-- 配置体检：静态检查 waf_rules 配置表里那些 `openresty -t` 抓不到、
-- 却会在运行期变成 500 / 全拒 / 安全绕过的错误。纯逻辑，不依赖 ngx，可单测。
-- lint(config) -> issues[{ level, where, msg }]；level 为 "error" | "warn"。
local M = {}

local KNOWN_METHODS = {
  GET = true, POST = true, PUT = true, PATCH = true,
  DELETE = true, HEAD = true, OPTIONS = true,
}
local BODY_METHODS = { POST = true, PUT = true, PATCH = true }

local function nonempty_array(t)
  return type(t) == "table" and #t > 0
end

local function has_value(list, val)
  if type(list) ~= "table" then return false end
  for _, v in ipairs(list) do
    if v == val then return true end
  end
  return false
end

-- 校验一条规则的 methods 字段（white / black 通用）
local function check_methods(rule, at, add)
  if rule.methods == nil then return end  -- 省略 = 不限方法，合法
  if type(rule.methods) ~= "table" then
    add("error", at, "methods 必须是数组，如 { \"POST\" }（省略表示不限方法）；写成标量会让该规则永不命中——黑名单上更会形成绕过")
    return
  end
  for _, m in ipairs(rule.methods) do
    if type(m) ~= "string" then
      add("error", at, "methods 元素必须是字符串，如 \"POST\"")
    elseif m ~= m:upper() or not KNOWN_METHODS[m:upper()] then
      add("error", at, "method \"" .. tostring(m)
        .. "\" 非法：必须大写且为标准 HTTP 方法，如 \"POST\"（代码大小写敏感，小写永不命中）")
    end
  end
end

-- 两条规则的方法适用范围是否重叠（任一为 nil=任意 即重叠）
local function methods_overlap(a, b)
  if a.methods == nil or b.methods == nil then return true end
  if type(a.methods) ~= "table" or type(b.methods) ~= "table" then return false end
  local set = {}
  for _, m in ipairs(a.methods) do
    if type(m) == "string" then set[m:upper()] = true end
  end
  for _, m in ipairs(b.methods) do
    if type(m) == "string" and set[m:upper()] then return true end
  end
  return false
end

local function methods_has_body(rule)
  if type(rule.methods) ~= "table" then return false end
  for _, m in ipairs(rule.methods) do
    if type(m) == "string" and BODY_METHODS[m:upper()] then return true end
  end
  return false
end

function M.lint(config)
  local issues = {}
  local function add(level, where, msg)
    issues[#issues + 1] = { level = level, where = where, msg = msg }
  end

  config = config or {}
  local schemas = config.schemas or {}
  local whitelist = config.whitelist or {}
  local blacklist = config.blacklist or {}

  if #whitelist == 0 then
    add("warn", "whitelist", "白名单为空，所有请求都会被默认拒绝（403 not_in_whitelist）")
  end

  -- 黑名单 path 集合，供白名单做遮蔽冲突检查
  local bl_paths = {}
  for i, rule in ipairs(blacklist) do
    local at = "blacklist[" .. i .. "]"
    if rule.path == nil and rule.pattern == nil then
      add("error", at, "规则既无 path 也无 pattern，永远不会命中（等于没拉黑）")
    end
    if rule.path ~= nil then bl_paths[rule.path] = true end
    if rule.body ~= nil then
      add("warn", at, "黑名单只看 URL、不做 body 校验，body 字段会被忽略")
    end
    check_methods(rule, at, add)
  end

  for i, rule in ipairs(whitelist) do
    local at = "whitelist[" .. i .. "]"
    if rule.path == nil and rule.pattern == nil then
      add("error", at, "规则既无 path 也无 pattern，永远不会命中（等于没配）")
    end
    if rule.path ~= nil and rule.pattern ~= nil then
      add("warn", at, "同时写了 path 和 pattern；代码里 path 优先，pattern 会被忽略")
    end
    check_methods(rule, at, add)
    -- body 引用的 schema 必须存在（-t 抓不到，会运行期 500 misconfigured）
    if rule.body ~= nil and schemas[rule.body] == nil then
      add("error", at, "body 引用了不存在的 schema：\"" .. tostring(rule.body)
        .. "\"；该接口所有请求会 500（misconfigured）")
    end
    -- body 配给不带请求体的方法（GET 等）→ 该接口请求被当空 body 一律 400
    if rule.body ~= nil and type(rule.methods) == "table" and not methods_has_body(rule) then
      add("error", at, "给不带请求体的方法（如 GET）配了 body 校验；这些请求 body 为 nil、会被判非对象一律 400")
    end
    -- 白名单 path 被黑名单遮蔽 → 先黑后白，会被先行 403 全拒
    if rule.path ~= nil and bl_paths[rule.path] then
      add("error", at, "白名单 path \"" .. rule.path
        .. "\" 同时出现在黑名单；黑名单先判，该接口会被先行 403 全拒")
    end
  end

  -- 同 path 且方法重叠的多条白名单规则：靠前者会短路靠后者（含 body 校验被绕过）
  for i = 1, #whitelist do
    for j = i + 1, #whitelist do
      local a, b = whitelist[i], whitelist[j]
      if a.path ~= nil and a.path == b.path and methods_overlap(a, b) then
        if (a.body or "<none>") ~= (b.body or "<none>") then
          add("error", "whitelist[" .. i .. "]&[" .. j .. "]",
            "同一 path \"" .. a.path .. "\" 的多条规则方法重叠且 body 配置不一致；"
            .. "match 取第一条命中，靠前规则会短路 body 校验，可能绕过")
        else
          add("warn", "whitelist[" .. i .. "]&[" .. j .. "]",
            "同一 path \"" .. a.path .. "\" 配了多条方法重叠的重复规则")
        end
      end
    end
  end

  -- 被引用情况，供 schema 未引用提示
  local referenced = {}
  for _, rule in ipairs(whitelist) do
    if rule.body then referenced[rule.body] = true end
  end

  for name, s in pairs(schemas) do
    local at = "schemas." .. tostring(name)
    if type(s) ~= "table" then
      add("error", at, "schema 必须是一个表")
    else
      if not nonempty_array(s.models) then
        add("error", at .. ".models", "models 为空或缺失，该 schema 会拒绝所有 model（422）")
      end

      if not nonempty_array(s.allowed_roles) then
        add("error", at .. ".allowed_roles", "allowed_roles 为空或缺失，所有 message 的 role 都会被拒（422）")
      elseif not has_value(s.allowed_roles, "user") then
        add("warn", at .. ".allowed_roles",
          "allowed_roles 不含 \"user\"；几乎所有 Chat 请求都带 user 角色，缺它会把正常对话全部拒（422）")
      end

      -- allowed_fields 整体先查根因，避免只暴露派生的「缺 model/messages」
      if not nonempty_array(s.allowed_fields) then
        add("error", at .. ".allowed_fields",
          "allowed_fields 缺失或不是非空数组；该 schema 会把所有请求字段当未知字段拒（全部 400）")
      else
        if not has_value(s.allowed_fields, "model") then
          add("error", at .. ".allowed_fields", "缺 \"model\"；带 model 的正常请求会被当未知字段拒（400）")
        end
        if not has_value(s.allowed_fields, "messages") then
          add("error", at .. ".allowed_fields", "缺 \"messages\"；带 messages 的正常请求会被当未知字段拒（400）")
        end
      end

      for _, key in ipairs({ "max_messages", "max_content_length", "max_total_length" }) do
        local v = s[key]
        if type(v) ~= "number" then
          add("error", at .. "." .. key, key .. " 未配成数字；运行期长度比较会报错导致 500")
        elseif v <= 0 or v ~= math.floor(v) then
          add("error", at .. "." .. key, key
            .. " 必须是大于 0 的整数；配成 <=0 会让该 schema 拒绝所有正常请求")
        end
      end

      if not referenced[name] then
        add("warn", at, "该 schema 没有被任何 whitelist 规则的 body 引用（可能是写错名字或多余定义）")
      end
    end
  end

  -- forbidden_headers：禁用请求头名单（可选）。ngx.req.get_headers() 的 key 全小写，
  -- 大写名永不命中 = 静默绕过，故对大小写从严（与 method 大小写检查同理）。
  local forbidden_headers = config.forbidden_headers
  if forbidden_headers ~= nil then
    if type(forbidden_headers) ~= "table" then
      add("error", "forbidden_headers", "forbidden_headers 必须是数组，如 { \"x-openclaw-model\" }")
    else
      for i, h in ipairs(forbidden_headers) do
        local at = "forbidden_headers[" .. i .. "]"
        if type(h) ~= "string" then
          add("error", at, "元素必须是字符串（请求头名）")
        elseif h == "" or h == "*" then
          add("error", at, "请求头名不能为空或裸 \"*\"；裸 \"*\" 会匹配所有请求头、拦死全部请求")
        elseif h ~= h:lower() then
          add("warn", at, "请求头名含大写 \"" .. tostring(h)
            .. "\"；运行时虽会自动转小写仍能命中，但建议直接写全小写以保持一致、避免误读")
        elseif h:find("*", 1, true) and h:sub(-1) ~= "*" then
          add("warn", at, "通配符 \"*\" 只支持放在末尾做前缀匹配（如 x-openclaw-*）；放在中间会被当字面量、永不命中")
        end
      end
    end
  end

  return issues
end

-- 统计某个级别的条数（"error" / "warn"）
function M.count(issues, level)
  local n = 0
  for _, i in ipairs(issues or {}) do
    if i.level == level then n = n + 1 end
  end
  return n
end

return M
