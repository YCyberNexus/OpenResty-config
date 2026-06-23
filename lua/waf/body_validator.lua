-- body 校验器：对解析后的 OpenAI Chat Completions 请求体做结构与内容约束。
-- 纯逻辑，输入已解析的 Lua table，不依赖 ngx，可单元测试。
-- validate(body) -> ok(boolean), err(table{code, field, message})
local BodyValidator = {}
BodyValidator.__index = BodyValidator

local function to_set(list)
  local s = {}
  for _, v in ipairs(list or {}) do s[v] = true end
  return s
end

function BodyValidator.new(opts)
  opts = opts or {}
  return setmetatable({
    opts = opts,
    models = to_set(opts.models),
    roles = to_set(opts.allowed_roles),
    fields = to_set(opts.allowed_fields),
  }, BodyValidator)
end

local function reject(code, field, message)
  return false, { code = code, field = field, message = message }
end

function BodyValidator:validate(body)
  if type(body) ~= "table" then
    return reject("schema", "body", "body must be a JSON object")
  end
  -- additionalProperties:false —— 顶层只允许白名单字段，未知字段一律拒绝
  for k in pairs(body) do
    if not self.fields[k] then
      return reject("schema", tostring(k), "unknown field")
    end
  end
  -- TODO(P3, 安全基线)：当前只深校 messages；allowed_fields 里其它字段(stop/user/数值等)仅过了
  -- "字段名白名单"、未校类型与边界(如 stop 可为超大数组、不受 max_content_length 约束)。目标约束见
  -- schemas/chat_completions.schema.json(stop maxItems 4、数值 range)，P3-3 迁移到 jsonschema 时收口。
  if body.messages == nil then
    return reject("schema", "messages", "messages is required")
  end
  if body.model == nil then
    return reject("schema", "model", "model is required")
  end
  if not self.models[body.model] then
    return reject("policy", "model", "model is not allowed")
  end

  if type(body.messages) ~= "table" or #body.messages == 0 then
    return reject("schema", "messages", "messages must be a non-empty array")
  end
  if #body.messages > self.opts.max_messages then
    return reject("policy", "messages", "too many messages")
  end
  local total = 0
  for i, msg in ipairs(body.messages) do
    local at = "messages[" .. i .. "]"
    if type(msg) ~= "table" then
      return reject("schema", at, "message must be an object")
    end
    if not self.roles[msg.role] then
      return reject("policy", at .. ".role", "message role is not allowed")
    end
    -- system 只允许出现在首位，因此最多 1 条（防伪造 system 注入越权指令）
    if msg.role == "system" and i ~= 1 then
      return reject("policy", at .. ".role", "system message must be the first message")
    end
    -- 起步骨架要求 content 为 string；多模态数组待 P3-5 用受控白名单扩展。
    -- 长度按字节计（#str）；中文/emoji 按字节会偏大，后续需补 utf8.len 双重口径。
    if type(msg.content) ~= "string" then
      return reject("schema", at .. ".content", "content must be a string")
    end
    if #msg.content > self.opts.max_content_length then
      return reject("policy", at .. ".content", "content is too long")
    end
    total = total + #msg.content
  end
  if total > self.opts.max_total_length then
    return reject("policy", "messages", "total content length is too long")
  end

  return true
end

return BodyValidator
