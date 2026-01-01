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
    // Derive a per-session key from session+hwid
    string keyMaterial = session + hwid;
    byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes(keyMaterial));

    var encrypted = new JsonObject();
    foreach (var kv in obj)
    {
        string plain = kv.Value!.ToString();
        string cipher = EncryptString(plain, key);
        encrypted[kv.Key] = cipher;
    }
    return encrypted;
}

static string EncryptString(string plainText, byte[] key)
{
    using var aes = Aes.Create();
    aes.Key = key;
    aes.GenerateIV();

    using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
    byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

    // Return IV + ciphertext as base64 so client can decrypt
    byte[] combined = new byte[aes.IV.Length + cipherBytes.Length];
    Buffer.BlockCopy(aes.IV, 0, combined, 0, aes.IV.Length);
    Buffer.BlockCopy(cipherBytes, 0, combined, aes.IV.Length, cipherBytes.Length);

    return Convert.ToBase64String(combined);
}
