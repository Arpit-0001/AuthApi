using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

string firebaseDb = Environment.GetEnvironmentVariable("FIREBASE_DB_URL")
    ?.TrimEnd('/')
    ?? throw new Exception("FIREBASE_DB_URL missing");

const string SECRET = "HMX_API_SECRET_2025";

app.MapGet("/", () => "GET-API service running");

// ======================================================
// POST /hmx/get-apis
// ======================================================
app.MapPost("/hmx/get-apis", async (HttpContext ctx) =>
{
    try
    {
        using var reader = new StreamReader(ctx.Request.Body);
        var raw = await reader.ReadToEndAsync();

        if (string.IsNullOrWhiteSpace(raw))
            return Results.Json(new { success = false, reason = "EMPTY_BODY" }, statusCode: 400);

        var body = JsonNode.Parse(raw) as JsonObject;
        if (body == null)
            return Results.Json(new { success = false, reason = "INVALID_JSON" }, statusCode: 400);

        string? session = body["session"]?.GetValue<string>();
        string? hwid = body["hwid"]?.GetValue<string>();

        if (session == null || hwid == null)
            return Results.Json(new { success = false, reason = "MISSING_FIELDS" }, statusCode: 400);

        // ---- validate session
        var sessionNode = await GetJson($"{firebaseDb}/sessions/{session}.json");
        if (sessionNode == null)
            return Results.Json(new { success = false, reason = "INVALID_SESSION" }, statusCode: 401);

        long expires = sessionNode["expires"]!.GetValue<long>();
        if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > expires)
            return Results.Json(new { success = false, reason = "SESSION_EXPIRED" }, statusCode: 401);

        if (sessionNode["hwid"]!.GetValue<string>() != hwid)
            return Results.Json(new { success = false, reason = "HWID_MISMATCH" }, statusCode: 403);

        string userId = sessionNode["id"]!.GetValue<string>();

        // ---- load data
        var user = await GetJson($"{firebaseDb}/users/{userId}.json");
        var apis = await GetJson($"{firebaseDb}/apis.json");

        if (user == null || apis == null)
            return Results.Json(new { success = false, reason = "DATA_LOAD_FAILED" }, statusCode: 500);

        // ---- encrypt allowed APIs
        var encryptedApis = new JsonObject();

        foreach (var api in apis.AsObject())
        {
            if (user[api.Key]?.GetValue<bool>() == true)
            {
                encryptedApis[api.Key] =
                    EncryptApiObject(api.Value!.AsObject(), session, hwid);
            }
        }

        return Results.Json(new
        {
            success = true,
            ttl = 30,
            apis = encryptedApis
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new
        {
            success = false,
            error = ex.Message
        }, statusCode: 500);
    }
});

app.Run();

// ======================================================
// HELPERS
// ======================================================
static JsonObject EncryptApiObject(JsonObject obj, string session, string hwid)
{
    string key = Hmac(session + hwid);

    var encrypted = new JsonObject();
    foreach (var kv in obj)
    {
        encrypted[kv.Key] = Hmac(kv.Value!.ToString() + key);
    }
    return encrypted;
}

static string Hmac(string raw)
{
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes("HMX_API_SECRET_2025"));
    return Convert.ToHexString(
        hmac.ComputeHash(Encoding.UTF8.GetBytes(raw))
    ).ToLower();
}

static async Task<JsonNode?> GetJson(string url)
{
    using HttpClient http = new();
    var res = await http.GetAsync(url);
    if (!res.IsSuccessStatusCode)
        return null;

    return JsonNode.Parse(await res.Content.ReadAsStringAsync());
}
