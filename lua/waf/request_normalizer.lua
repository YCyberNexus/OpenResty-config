-- HTTP 请求规范化：严格 Query 解码/类型转换、媒体类型和请求头规范化。
-- 该模块不依赖 ngx，便于在上线前用纯 LuaJIT 验证配置行为。
local M = {}

local function failure(reason, field, status)
  return nil, { reason = reason, field = field, status = status or 400 }
end

local function has_control(value)
  return type(value) ~= "string" or value:find("[%z\1-\31\127]") ~= nil
end

function M.media_type(content_type)
  if type(content_type) ~= "string" or #content_type > 1024 or has_control(content_type) then
    return nil
  end
  local base = content_type:match("^%s*([^;]+)")
  if not base then return nil end
  base = base:match("^(.-)%s*$"):lower()
  if not base:match("^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$") then
    return nil
  end
  return base
end

function M.media_type_allowed(content_type, allowed)
  local base = M.media_type(content_type)
  if not base then return false end
  for _, value in ipairs(allowed or {}) do
    if base == value then return true, base end
  end
  return false, base
end

local function decode_component(value)
  local output, i = {}, 1
  while i <= #value do
    local char = value:sub(i, i)
    if char == "+" then
      output[#output + 1] = " "
      i = i + 1
    elseif char == "%" then
      local hex = value:sub(i + 1, i + 2)
      if #hex ~= 2 or not hex:match("^[0-9A-Fa-f][0-9A-Fa-f]$") then return nil end
      local byte = tonumber(hex, 16)
      if byte == 0 or byte < 32 or byte == 127 then return nil end
      output[#output + 1] = string.char(byte)
      i = i + 3
    else
      local byte = char:byte()
      if byte == 0 or byte < 32 or byte == 127 then return nil end
      output[#output + 1] = char
      i = i + 1
    end
  end
  return table.concat(output)
end

local function encode_component(value)
  value = tostring(value)
  return (value:gsub("([^A-Za-z0-9._~-])", function(char)
    return string.format("%%%02X", char:byte())
  end))
end

local function schema_type(schema)
  if type(schema) ~= "table" then return nil end
  if type(schema.type) == "string" then return schema.type end
  local selected
  for _, value in ipairs(type(schema.type) == "table" and schema.type or {}) do
    if value ~= "null" then
      if selected then return nil end
      selected = value
    end
  end
  return selected
end

local function finite(value)
  return value ~= nil and value == value and value ~= math.huge and value ~= -math.huge
end

local function parse_number(value)
  if not (value:match("^-?%d+$") or value:match("^-?%d+%.%d+$")
    or value:match("^-?%d+[eE][+-]?%d+$")
    or value:match("^-?%d+%.%d+[eE][+-]?%d+$")) then return nil end
  local number = tonumber(value)
  return finite(number) and number or nil
end

local function convert_scalar(value, schema)
  local wanted = schema_type(schema)
  if wanted == "string" then return value end
  if wanted == "integer" then
    if not value:match("^-?%d+$") then return nil end
    local number = tonumber(value)
    if not finite(number) or number ~= math.floor(number) then return nil end
    return number
  end
  if wanted == "number" then return parse_number(value) end
  if wanted == "boolean" then
    if value == "true" then return true end
    if value == "false" then return false end
  end
  return nil
end

local function scalar_string(value)
  if type(value) == "boolean" then return value and "true" or "false" end
  return tostring(value)
end

function M.parse_query(raw, schema, max_bytes, max_pairs)
  raw = raw or ""
  if type(raw) ~= "string" then return failure("invalid_query", "query") end
  if #raw > (max_bytes or 8192) then
    return failure("query_too_large", "query", 414)
  end
  local decoded, pair_count = {}, 0
  if raw ~= "" then
    for pair in (raw .. "&"):gmatch("(.-)&") do
      if pair == "" then return failure("invalid_query", "query") end
      pair_count = pair_count + 1
      if pair_count > (max_pairs or 64) then return failure("too_many_query_parameters", "query") end
      local equal = pair:find("=", 1, true)
      local raw_key = equal and pair:sub(1, equal - 1) or pair
      local raw_value = equal and pair:sub(equal + 1) or ""
      local key, value = decode_component(raw_key), decode_component(raw_value)
      if not key or key == "" or not value then return failure("invalid_query", "query") end
      local prior = decoded[key]
      if prior == nil then
        decoded[key] = value
      elseif type(prior) == "table" then
        prior[#prior + 1] = value
      else
        decoded[key] = { prior, value }
      end
    end
  end

  local properties = type(schema) == "table" and schema.properties or {}
  local typed = {}
  for key, raw_value in pairs(decoded) do
    local property = properties[key]
    if not property then
      typed[key] = raw_value
    elseif schema_type(property) == "array" then
      local values = type(raw_value) == "table" and raw_value or { raw_value }
      local converted = {}
      for i, item in ipairs(values) do
        converted[i] = convert_scalar(item, property.items)
        if converted[i] == nil then
          return failure("query_type", "query." .. key)
        end
      end
      typed[key] = converted
    else
      if type(raw_value) == "table" then
        return failure("duplicate_query_parameter", "query." .. key)
      end
      local converted = convert_scalar(raw_value, property)
      if converted == nil then return failure("query_type", "query." .. key) end
      typed[key] = converted
    end
  end

  local keys = {}
  for key in pairs(typed) do keys[#keys + 1] = key end
  table.sort(keys)
  local encoded = {}
  for _, key in ipairs(keys) do
    local value = typed[key]
    if type(value) == "table" then
      for _, item in ipairs(value) do
        encoded[#encoded + 1] = encode_component(key) .. "=" .. encode_component(scalar_string(item))
      end
    else
      encoded[#encoded + 1] = encode_component(key) .. "=" .. encode_component(scalar_string(value))
    end
  end
  return typed, table.concat(encoded, "&")
end

local function header_name(value)
  if type(value) ~= "string" then return nil end
  local normalized = value:lower():gsub("_", "-")
  if not normalized:match("^[a-z0-9!#$%%&'*+.^_`|~-]+$") then return nil end
  return normalized
end

function M.normalize_headers(headers)
  local normalized = {}
  for key, value in pairs(headers or {}) do
    local name = header_name(key)
    if not name then return failure("invalid_header", tostring(key)) end
    if normalized[name] ~= nil or type(value) == "table" then
      return failure("duplicate_header", name)
    end
    value = tostring(value)
    if #value > 16384 or has_control(value) then
      return failure("invalid_header", name)
    end
    normalized[name] = value
  end
  return normalized
end

function M.safe_header_value(value)
  return type(value) == "string" and #value <= 16384 and not has_control(value)
end

return M
