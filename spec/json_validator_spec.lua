describe("json_validator", function()
  local JsonValidator, fixtures, config, json

  before_each(function()
    package.loaded["waf.json_validator"] = nil
    JsonValidator = require("waf.json_validator")
    fixtures = require("spec.fixtures")
    config = fixtures.config()
    json = fixtures.json
  end)

  local function validator(name)
    return JsonValidator.new(config.schemas[name], {
      null_value = json.null,
      array_mt = json.array_mt,
    })
  end

  it("accepts the documented search request", function()
    assert.is_true(validator("knowledge_search_request"):validate(fixtures.search_request()))
  end)

  it("applies top_k default by allowing the field to be omitted", function()
    assert.is_true(validator("knowledge_search_request"):validate({ query = "query" }))
  end)

  it("rejects blank and over-limit queries", function()
    local ok1, err1 = validator("knowledge_search_request"):validate({ query = "   " })
    local ok2, err2 = validator("knowledge_search_request"):validate({ query = string.rep("中", 4001) })
    assert.is_false(ok1)
    assert.are.equal("query", err1.field)
    assert.is_false(ok2)
    assert.are.equal("query", err2.field)
  end)

  it("counts UTF-8 characters rather than bytes for query length", function()
    assert.is_true(validator("knowledge_search_request"):validate({ query = string.rep("中", 4000) }))
  end)

  it("rejects top_k outside 1 through 50 and rejects non-integers", function()
    assert.is_false(validator("knowledge_search_request"):validate({ query = "q", top_k = 0 }))
    assert.is_false(validator("knowledge_search_request"):validate({ query = "q", top_k = 51 }))
    assert.is_false(validator("knowledge_search_request"):validate({ query = "q", top_k = 1.5 }))
  end)

  it("rejects unknown request fields", function()
    local ok, err = validator("knowledge_search_request"):validate({ query = "q", evil = true })
    assert.is_false(ok)
    assert.are.equal("evil", err.field)
  end)

  it("distinguishes an empty JSON array from an empty object", function()
    local schema = { type = "array", max_items = 1, items = { type = "string" } }
    local check = JsonValidator.new(schema, { array_mt = json.array_mt })
    assert.is_true(check:validate(json.array({})))
    assert.is_false(check:validate({}))
  end)

  it("accepts nullable result fields only when represented as JSON null", function()
    local response = fixtures.search_response()
    response.results[1].page_number = json.null
    response.results[1].section_title = json.null
    assert.is_true(validator("knowledge_search_response"):validate(response, {
      request_body = fixtures.search_request(),
    }))
  end)

  it("rejects traversal in asset and metadata paths", function()
    local response = fixtures.search_response()
    response.results[1].asset_key = "../secrets.txt"
    local ok, err = validator("knowledge_search_response"):validate(response, {
      request_body = fixtures.search_request(),
    })
    assert.is_false(ok)
    assert.are.equal("results[1].asset_key", err.field)
  end)

  it("rejects undocumented metadata fields", function()
    local response = fixtures.search_response()
    response.results[1].metadata.internal_ip = "10.0.0.1"
    local ok, err = validator("knowledge_search_response"):validate(response, {
      request_body = fixtures.search_request(),
    })
    assert.is_false(ok)
    assert.are.equal("results[1].metadata.internal_ip", err.field)
  end)
end)
