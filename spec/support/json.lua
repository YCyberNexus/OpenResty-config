-- 极简 JSON 编解码，仅供测试替身使用（替代 OpenResty 的 cjson.safe）。
-- 接口与 cjson.safe 一致：decode(str)->value|nil,err ；encode(value)->str。
local M = {}

local ESC = { ['"'] = '"', ['\\'] = '\\', ['/'] = '/', n = '\n', t = '\t', r = '\r', b = '\b', f = '\f' }

local decode_value

local function skip_ws(s, i)
  local _, j = s:find("^%s*", i)
  return j + 1
end

local function decode_string(s, i)
  if s:sub(i, i) ~= '"' then error("expected string") end
  i = i + 1
  local buf = {}
  while i <= #s do
    local c = s:sub(i, i)
    if c == '"' then return table.concat(buf), i + 1 end
    if c == '\\' then
      local n = s:sub(i + 1, i + 1)
      buf[#buf + 1] = ESC[n] or n
      i = i + 2
    else
      buf[#buf + 1] = c
      i = i + 1
    end
  end
  error("unterminated string")
end

local function decode_number(s, i)
  local j = i
  while j <= #s and s:sub(j, j):match("[%d%.eE%+%-]") do j = j + 1 end
  return tonumber(s:sub(i, j - 1)), j
end

local function decode_array(s, i)
  i = skip_ws(s, i + 1)
  local arr = {}
  if s:sub(i, i) == ']' then return arr, i + 1 end
  while true do
    local v
    v, i = decode_value(s, i)
    arr[#arr + 1] = v
    i = skip_ws(s, i)
    local c = s:sub(i, i)
    if c == ',' then i = skip_ws(s, i + 1)
    elseif c == ']' then return arr, i + 1
    else error("bad array") end
  end
end

local function decode_object(s, i)
  i = skip_ws(s, i + 1)
  local obj = {}
  if s:sub(i, i) == '}' then return obj, i + 1 end
  while true do
    i = skip_ws(s, i)
    local key
    key, i = decode_string(s, i)
    i = skip_ws(s, i)
    if s:sub(i, i) ~= ':' then error("expected colon") end
    local v
    v, i = decode_value(s, skip_ws(s, i + 1))
    obj[key] = v
    i = skip_ws(s, i)
    local c = s:sub(i, i)
    if c == ',' then i = i + 1
    elseif c == '}' then return obj, i + 1
    else error("bad object") end
  end
end

function decode_value(s, i)
  i = skip_ws(s, i)
  local c = s:sub(i, i)
  if c == '{' then return decode_object(s, i)
  elseif c == '[' then return decode_array(s, i)
  elseif c == '"' then return decode_string(s, i)
  elseif c == 't' then return true, i + 4
  elseif c == 'f' then return false, i + 5
  elseif c == 'n' then return nil, i + 4
  else return decode_number(s, i) end
end

function M.decode(s)
  if type(s) ~= "string" then return nil, "not a string" end
  local ok, v = pcall(decode_value, s, 1)
  if not ok then return nil, v end
  return v
end

local function encode_value(v)
  local t = type(v)
  if t == "string" then return '"' .. v:gsub('[\\"]', '\\%0') .. '"' end
  if t == "number" or t == "boolean" then return tostring(v) end
  if t == "table" then
    if #v > 0 then
      local parts = {}
      for _, item in ipairs(v) do parts[#parts + 1] = encode_value(item) end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    local parts = {}
    for k, val in pairs(v) do parts[#parts + 1] = '"' .. tostring(k) .. '":' .. encode_value(val) end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  return "null"
end

function M.encode(v) return encode_value(v) end

return M
