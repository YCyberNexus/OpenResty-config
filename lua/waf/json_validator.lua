-- 受限 JSON Schema 校验器。
--
-- 这里只实现本项目接口契约实际使用的子集：object / array / string /
-- integer / number / boolean / null、required、additionalProperties=false、
-- 长度/范围/枚举/格式。模块不依赖 ngx，也不包含任何业务 URL 或业务字段知识。
local JsonValidator = {}
JsonValidator.__index = JsonValidator

local function reject(code, field, message)
  return false, { code = code, field = field, message = message }
end

local function contains(list, wanted)
  if type(list) ~= "table" then return false end
  for _, value in ipairs(list) do
    if value == wanted then return true end
  end
  return false
end

local function child_path(path, key)
  if type(key) == "number" then
    return (path ~= "" and path or "body") .. "[" .. key .. "]"
  end
  if path == "" or path == "body" then return tostring(key) end
  return path .. "." .. tostring(key)
end

-- 返回 UTF-8 字符数；非法、过长或代理项编码返回 nil。
local function utf8_length(value)
  local i, count, size = 1, 0, #value
  while i <= size do
    local b1 = value:byte(i)
    local width
    if b1 <= 0x7f then
      width = 1
    elseif b1 >= 0xc2 and b1 <= 0xdf then
      local b2 = value:byte(i + 1)
      if not b2 or b2 < 0x80 or b2 > 0xbf then return nil end
      width = 2
    elseif b1 >= 0xe0 and b1 <= 0xef then
      local b2, b3 = value:byte(i + 1), value:byte(i + 2)
      if not b2 or not b3 or b3 < 0x80 or b3 > 0xbf then return nil end
      if b1 == 0xe0 then
        if b2 < 0xa0 or b2 > 0xbf then return nil end
      elseif b1 == 0xed then
        if b2 < 0x80 or b2 > 0x9f then return nil end
      elseif b2 < 0x80 or b2 > 0xbf then
        return nil
      end
      width = 3
    elseif b1 >= 0xf0 and b1 <= 0xf4 then
      local b2, b3, b4 = value:byte(i + 1), value:byte(i + 2), value:byte(i + 3)
      if not b2 or not b3 or not b4
        or b3 < 0x80 or b3 > 0xbf or b4 < 0x80 or b4 > 0xbf then
        return nil
      end
      if b1 == 0xf0 then
        if b2 < 0x90 or b2 > 0xbf then return nil end
      elseif b1 == 0xf4 then
        if b2 < 0x80 or b2 > 0x8f then return nil end
      elseif b2 < 0x80 or b2 > 0xbf then
        return nil
      end
      width = 4
    else
      return nil
    end
    i = i + width
    count = count + 1
  end
  return count
end

local function is_dense_array(value, array_mt)
  if type(value) ~= "table" then return false end
  if array_mt and getmetatable(value) == array_mt then return true end

  local count, highest = 0, 0
  for key in pairs(value) do
    if type(key) ~= "number" or key < 1 or key ~= math.floor(key) then
      return false
    end
    count = count + 1
    if key > highest then highest = key end
  end
  -- 空 table 在没有 array metatable 时按 object 处理，避免把 {} 当成 []。
  return count > 0 and count == highest
end

local function is_finite(value)
  return value == value and value ~= math.huge and value ~= -math.huge
end

local function has_control(value)
  return value:find("[%z\1-\31\127]") ~= nil
end

local function valid_relative_path(value)
  if value == "" or value:sub(1, 1) == "/" or value:find("\\", 1, true)
    or has_control(value) then
    return false
  end
  for segment in value:gmatch("[^/]+") do
    if segment == "." or segment == ".." then return false end
  end
  return not value:find("//", 1, true) and value:sub(-1) ~= "/"
end

local function valid_absolute_path(value)
  return value:sub(1, 1) == "/" and valid_relative_path(value:sub(2))
end

local FORMATS = {
  uuid = function(value)
    return value:match("^[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]%-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]%-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]%-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]%-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]$") ~= nil
  end,
  relative_path = valid_relative_path,
  absolute_path = valid_absolute_path,
  filename = function(value)
    return value ~= "" and not value:find("/", 1, true)
      and not value:find("\\", 1, true) and not has_control(value)
  end,
}

function JsonValidator.new(schema, opts)
  opts = opts or {}
  return setmetatable({
    schema = schema or {},
    null_value = opts.null_value,
    array_mt = opts.array_mt,
  }, JsonValidator)
end

function JsonValidator:_is_null(value)
  return self.null_value ~= nil and value == self.null_value
end

function JsonValidator:_matches_type(value, wanted)
  if wanted == "null" then return self:_is_null(value) end
  if self:_is_null(value) then return false end
  if wanted == "object" then
    return type(value) == "table" and not is_dense_array(value, self.array_mt)
  end
  if wanted == "array" then return is_dense_array(value, self.array_mt) end
  if wanted == "integer" then
    return type(value) == "number" and is_finite(value) and value == math.floor(value)
  end
  if wanted == "number" then return type(value) == "number" and is_finite(value) end
  return type(value) == wanted
end

function JsonValidator:_type_allowed(value, declared)
  if type(declared) == "string" then return self:_matches_type(value, declared) end
  if type(declared) == "table" then
    for _, wanted in ipairs(declared) do
      if self:_matches_type(value, wanted) then return true end
    end
  end
  return false
end

function JsonValidator:_validate(schema, value, path)
  if type(schema) ~= "table" or schema.type == nil then
    return reject("schema", path ~= "" and path or "body", "validator schema is invalid")
  end

  if not self:_type_allowed(value, schema.type) then
    return reject("schema", path ~= "" and path or "body", "unexpected JSON type")
  end
  if self:_is_null(value) then return true end

  if schema.enum and not contains(schema.enum, value) then
    return reject("policy", path, "value is not allowed")
  end

  local value_type = type(value)
  if value_type == "string" then
    local length = utf8_length(value)
    if not length then return reject("schema", path, "string is not valid UTF-8") end
    if schema.min_length and length < schema.min_length then
      return reject("policy", path, "string is too short")
    end
    if schema.max_length and length > schema.max_length then
      return reject("policy", path, "string is too long")
    end
    if schema.max_bytes and #value > schema.max_bytes then
      return reject("policy", path, "string byte length is too large")
    end
    if schema.prefix and value:sub(1, #schema.prefix) ~= schema.prefix then
      return reject("policy", path, "string prefix is not allowed")
    end
    if schema.non_blank and value:match("^%s*$") then
      return reject("policy", path, "string must not be blank")
    end
    if schema.trimmed and value ~= value:match("^%s*(.-)%s*$") then
      return reject("policy", path, "string must be trimmed")
    end
    if schema.format then
      local check = FORMATS[schema.format]
      if not check or not check(value) then
        return reject("policy", path, "string format is not allowed")
      end
    end
    return true
  end

  if value_type == "number" then
    if schema.minimum ~= nil and value < schema.minimum then
      return reject("policy", path, "number is below minimum")
    end
    if schema.maximum ~= nil and value > schema.maximum then
      return reject("policy", path, "number is above maximum")
    end
    return true
  end

  if value_type ~= "table" then return true end

  if self:_matches_type(value, "array") then
    local count = #value
    if schema.min_items and count < schema.min_items then
      return reject("policy", path, "array has too few items")
    end
    if schema.max_items and count > schema.max_items then
      return reject("policy", path, "array has too many items")
    end
    for i, item in ipairs(value) do
      local ok, err = self:_validate(schema.items, item, child_path(path, i))
      if not ok then return false, err end
    end
    return true
  end

  local properties = schema.properties or {}
  for _, key in ipairs(schema.required or {}) do
    if rawget(value, key) == nil then
      return reject("schema", child_path(path, key), "required field is missing")
    end
  end

  local property_count = 0
  for key, item in pairs(value) do
    property_count = property_count + 1
    if type(key) ~= "string" then
      return reject("schema", path ~= "" and path or "body", "object key must be a string")
    end
    local child_schema = properties[key]
    if child_schema == nil then
      if schema.additional_properties == false then
        return reject("schema", child_path(path, key), "unknown field")
      end
    else
      local ok, err = self:_validate(child_schema, item, child_path(path, key))
      if not ok then return false, err end
    end
  end
  if schema.max_properties and property_count > schema.max_properties then
    return reject("policy", path ~= "" and path or "body", "object has too many fields")
  end
  return true
end

function JsonValidator:validate(value)
  local ok, err = self:_validate(self.schema, value, "")
  if not ok then return false, err end
  return true
end

JsonValidator.formats = FORMATS

return JsonValidator
