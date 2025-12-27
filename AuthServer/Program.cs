using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

const string SECRET = "HMX_BY_MR_ARPIT_120";

string firebaseDb =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")!
        .TrimEnd('/');

app.MapGet("/", () => "API Service running");

// =======================================================
// POST /hmx/get-apis
// =======================================================
app.MapPost("/hmx/get-apis", async (HttpContext ctx) =>
{
    using var reader = new StreamReader(ctx.Request.Body);
    var body = JsonNode.Parse(await reader.ReadToEndAsync());

    if (body == null)
        return Results.BadRequest();

    string session = body["session"]!.GetValue<string>();
    string hwid = body["hwid"]!.GetValue<string>();
    string feature = body["feature"]!.GetValue<string>();

    long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    // ---------- SESSION ----------
    var sessionNode = await GetJson($"{firebaseDb}/sessions/{session}.json");
    if (sessionNode == null)
        return Results.Unauthorized();

    string userId = sessionNode["userId"]!.GetValue<string>();
    string storedHwid = sessionNode["hwid"]!.GetValue<string>();
    long expiry = sessionNode["expiry"]!.GetValue<long>();

    if (storedHwid != hwid || now > expiry)
        return Results.Unauthorized();

    // ---------- USER ----------
    var user = await GetJson($"{firebaseDb}/users/{userId}.json");
    if (user == null)
        return Results.Unauthorized();

    bool allowed = user[feature]?.GetValue<bool>() ?? false;
    if (!allowed)
        return Results.Forbid();

    // ---------- APIS ----------
    var apis = await GetJson($"{firebaseDb}/apis/{feature}.json");
    if (apis == null)
        return Results.NotFound();

    string key = SECRET + session + hwid;

    var encrypted = new JsonObject();
    foreach (var api in apis.AsObject())
    {
        encrypted[api.Key] =
            Encrypt(api.Value!.GetValue<string>(), key);
    }

    return Results.Json(new
    {
        success = true,
        ttl = 30,
        apis = encrypted
    });
});

app.Run();

// =======================================================
// HELPERS
// =======================================================

static string Encrypt(string plain, string key)
{
    using var aes = Aes.Create();
    aes.Key = SHA256.HashData(Encoding.UTF8.GetBytes(key));
    aes.GenerateIV();

    using var enc = aes.CreateEncryptor();
    byte[] data = Encoding.UTF8.GetBytes(plain);
    byte[] cipher = enc.TransformFinalBlock(data, 0, data.Length);

    return Convert.ToBase64String(
        aes.IV.Concat(cipher).ToArray()
    );
}

static async Task<JsonNode?> GetJson(string url)
{
    using HttpClient http = new();
    var res = await http.GetAsync(url);
    if (!res.IsSuccessStatusCode)
        return null;

    return JsonNode.Parse(await res.Content.ReadAsStringAsync());
}
