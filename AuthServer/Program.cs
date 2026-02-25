using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

const string SECRET = "RAVEN_BY_MR_ARPIT_120";

string firebaseDb =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")!
    .TrimEnd('/');

app.MapGet("/", () => "Raven Auth Running");


// ======================================================
// POST /raven/auth
// ======================================================

app.MapPost("/raven/auth", async (HttpContext ctx) =>
{
    try
    {
        using var reader = new StreamReader(ctx.Request.Body);
        string raw = await reader.ReadToEndAsync();

        JsonNode? node = JsonNode.Parse(raw);
        
        if (node is not JsonObject body)
        {
            return Results.Json(new
            {
                success = false,
                error = "invalid_json"
            });
        }
        if (body == null)
            return Results.Json(new { success = false });

        string username = body["v1"]!.GetValue<string>();
        string hwid = body["v2"]!.GetValue<string>();
        string password = body["v3"]!.GetValue<string>();
        string version = body["v4"]!.GetValue<string>();
        string nonce = body["v5"]!.GetValue<string>();
        string clientHmac = body["v6"]!.GetValue<string>();
        string? referral = body["v7"]?.GetValue<string>();

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // ======================================================
        // VERSION CHECK
        // ======================================================

        var appCfg = await GetJson($"{firebaseDb}/app.json");

        if (appCfg == null)
            return Results.Json(new { success = false });

        string serverVersion = appCfg["version"]!.GetValue<string>();

        if (version != serverVersion)
        {
            return Results.Json(new
            {
                success = false,
                reason = "version_mismatch"
            });
        }

        // ======================================================
        // VERIFY HMAC
        // ======================================================

        string rawSig = SECRET + username + password + version + nonce;
        string expected = ComputeHmac(rawSig);

        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(clientHmac),
                Convert.FromHexString(expected)))
        {
            return Results.Json(new
            {
                success = false,
                reason = "invalid_signature"
            });
        }

        // ======================================================
        // HWID BAN CHECK
        // ======================================================

        var hwidNode = await GetJson($"{firebaseDb}/hwid_attempts/{hwid}.json");

        if (hwidNode != null)
        {
            bool banned = bool.Parse(hwidNode["banned"]!.GetValue<string>());
            long bannedUntil = long.Parse(hwidNode["banned_until"]!.GetValue<string>());

            if (banned && now < bannedUntil)
            {
                return Results.Json(new
                {
                    success = false,
                    reason = "hwid_banned"
                });
            }

            if (banned && now >= bannedUntil)
            {
                hwidNode["banned"] = "false";
                hwidNode["attempt_remaining"] = "3";
                hwidNode["banned_until"] = "0";

                await PutJson($"{firebaseDb}/hwid_attempts/{hwid}.json", hwidNode);
            }
        }

        // ======================================================
        // LOAD USERS
        // ======================================================

        var users = await GetJson($"{firebaseDb}/users.json");

        if (users == null)
            return Results.Json(new { success = false });

        string? userKey = null;
        JsonNode? userNode = null;

        foreach (var u in users.AsObject())
        {
            string dbUser = u.Value!["name"]!.GetValue<string>();
            string dbPass = u.Value!["password"]!.GetValue<string>();

            if (dbUser == username && dbPass == password)
            {
                userKey = u.Key;
                userNode = u.Value;
                break;
            }
        }

        // ======================================================
        // INVALID CREDENTIALS
        // ======================================================

        if (userNode == null)
        {
            int remaining = await DecreaseAttempts(hwid);

            return Results.Json(new
            {
                success = false,
                reason = "Invalid_credential",
                remaining_attempts = remaining
            });
        }

        // ======================================================
        // HWID POLICY
        // ======================================================

        var status = userNode["status"]!.AsObject();

        bool hwidLocked = bool.Parse(status["hwid_locked"]!.GetValue<string>());
        var hwids = status["hwids"]!.AsObject();

        if (!hwidLocked)
        {
            bool exists = hwids.Any(x => x.Value!.GetValue<string>() == hwid);

            if (!exists)
            {
                var empty = hwids.FirstOrDefault(x => string.IsNullOrEmpty(x.Value!.GetValue<string>()));

                if (empty.Key != null)
                {
                    hwids[empty.Key] = hwid;

                    await PutJson($"{firebaseDb}/users/{userKey}/status/hwids.json", hwids);
                }
                else
                {
                    status["hwid_locked"] = "true";

                    await PutJson($"{firebaseDb}/users/{userKey}/status.json", status);

                    return Results.Json(new
                    {
                        success = false,
                        reason = "new_user"
                    });
                }
            }
        }

// ======================================================
// CREATE SESSION
// ======================================================

string session = GenerateSession();
long expiry = now + 1800;

await PutJson($"{firebaseDb}/sessions/{session}.json", new JsonObject
{
    ["belong_user"] = $"{userKey}_{hwid}",
    ["s_expiry"] = expiry.ToString()
});


// ======================================================
// BUILD ACCOUNTS OUTPUT
// ======================================================

var accountsNode = userNode["accounts"]?.AsObject();
var accountsOut = new JsonObject();

if (accountsNode != null)
{
    foreach (var acc in accountsNode)
    {
        string accName = acc.Value!["account_name"]!.GetValue<string>();
        string accPass = acc.Value!["account_password"]!.GetValue<string>();

        string signedPassword = ComputeHmac(SECRET + session + accPass);

        accountsOut[acc.Key] = new JsonObject
        {
            ["account_name"] = accName,
            ["account_password"] = signedPassword
        };
    }
}


// ======================================================
// RESPONSE
// ======================================================

return Results.Json(new
{
    success = true,
    session = session,
    expiry = expiry,
    accounts = accountsOut
});
}
catch (Exception ex)
{
    return Results.Json(new
    {
        success = false,
        error = ex.Message
    });
}
});


// ======================================================
// HELPERS
// ======================================================

static string ComputeHmac(string raw)
{
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SECRET));

    return Convert.ToHexString(
        hmac.ComputeHash(Encoding.UTF8.GetBytes(raw))
    ).ToLower();
}

static string GenerateSession()
{
    byte[] bytes = RandomNumberGenerator.GetBytes(32);
    return Convert.ToHexString(bytes).ToLower();
}

static async Task<JsonNode?> GetJson(string url)
{
    using HttpClient http = new();

    var res = await http.GetAsync(url);

    if (!res.IsSuccessStatusCode)
        return null;

    return JsonNode.Parse(await res.Content.ReadAsStringAsync());
}

static async Task PutJson(string url, JsonNode body)
{
    using HttpClient http = new();

    await http.PutAsync(
        url,
        new StringContent(
            body.ToJsonString(),
            Encoding.UTF8,
            "application/json"));
}

static async Task<int> DecreaseAttempts(string hwid)
{
    string baseUrl = Environment.GetEnvironmentVariable("FIREBASE_DB_URL")!
        .TrimEnd('/');

    var node = await GetJson($"{baseUrl}/hwid_attempts/{hwid}.json");

    long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    int remain = node?["attempt_remaining"] != null
        ? int.Parse(node["attempt_remaining"]!.GetValue<string>())
        : 3;

    remain--;

    if (remain <= 0)
    {
        await PutJson($"{baseUrl}/hwid_attempts/{hwid}.json", new JsonObject
        {
            ["banned"] = "true",
            ["banned_until"] = (now + 86400).ToString(),
            ["attempt_remaining"] = "0"
        });

        return 0;
    }

    await PutJson($"{baseUrl}/hwid_attempts/{hwid}.json", new JsonObject
    {
        ["banned"] = "false",
        ["banned_until"] = "0",
        ["attempt_remaining"] = remain.ToString()
    });

    return remain;
}

app.Run();
