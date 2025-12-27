using var reader = new StreamReader(ctx.Request.Body);
var rawBody = await reader.ReadToEndAsync();

if (string.IsNullOrWhiteSpace(rawBody))
    return Results.Json(new { success = false, reason = "EMPTY_BODY" }, statusCode: 400);

var body = JsonNode.Parse(rawBody) as JsonObject;
if (body == null)
    return Results.Json(new { success = false, reason = "INVALID_JSON" }, statusCode: 400);

string? session = body["session"]?.GetValue<string>();
string? hwid = body["hwid"]?.GetValue<string>();
string? feature = body["feature"]?.GetValue<string>();

if (string.IsNullOrEmpty(session) ||
    string.IsNullOrEmpty(hwid) ||
    string.IsNullOrEmpty(feature))
{
    return Results.Json(new
    {
        success = false,
        reason = "MISSING_FIELDS"
    }, statusCode: 400);
}
