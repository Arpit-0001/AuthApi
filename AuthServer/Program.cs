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
        JsonObject? body;
        
        try
        {
            body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
        }
        catch
        {
            return Results.Json(new
            {
                success = false,
                error = "invalid_json"
            });
        }
        
        if (body == null)
        {
            return Results.Json(new
            {
                success = false,
                error = "invalid_json"
            });
        }

        string username = body["v1"]?.ToString() ?? "";
        string hwid = body["v2"]?.ToString() ?? "";
        string password = body["v3"]?.ToString() ?? "";
        string version = body["v4"]?.ToString() ?? "";
        string nonce = body["v5"]?.ToString() ?? "";
        string clientHmac = body["v6"]?.ToString() ?? "";
        string? referral = body["v7"]?.ToString();

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
            bool banned = false;
            long bannedUntil = 0;
            
            bool.TryParse(hwidNode?["banned"]?.ToString(), out banned);
            long.TryParse(hwidNode?["banned_until"]?.ToString(), out bannedUntil);

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
                hwidNode["banned"] = false;
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

        var usersObj = users as JsonObject;
        if (usersObj == null)
            return Results.Json(new { success = false });

        foreach (var u in usersObj)
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
    
    /* ---------- READ HWID LOCK SAFELY ---------- */
    
    bool hwidLocked = false;
    
    if (status["hwid_locked"] != null)
    {
        if (status["hwid_locked"] is JsonValue v)
        {
            if (v.TryGetValue<bool>(out var b))
                hwidLocked = b;
            else if (v.TryGetValue<string>(out var s))
                bool.TryParse(s, out hwidLocked);
        }
    }
    
    /* ---------- GET HWID ARRAY SAFELY ---------- */
    
    JsonArray hwidArray;
    
    if (status["hwids"] is JsonArray arr)
    {
        hwidArray = arr;
    }
    else
    {
        hwidArray = new JsonArray(null, "", "");
    }
    
    /* ---------- REGISTER HWID ---------- */
    
    if (!hwidLocked)
    {
        bool exists = hwidArray.Any(x => x?.ToString() == hwid);
    
        if (!exists)
        {
            int emptyIndex = -1;
    
            for (int i = 0; i < hwidArray.Count; i++)
            {
                if (string.IsNullOrEmpty(hwidArray[i]?.ToString()))
                {
                    emptyIndex = i;
                    break;
                }
            }
    
            if (emptyIndex != -1)
            {
                hwidArray[emptyIndex] = hwid;
    
                await PutJson(
                    $"{firebaseDb}/users/{userKey}/status/hwids.json",
                    hwidArray
                );
            }
            else
            {
                status["hwid_locked"] = true;
    
                await PutJson(
                    $"{firebaseDb}/users/{userKey}/status.json",
                    status
                );
    
                return Results.Json(new
                {
                    success = false,
                    reason = "hwid_limit_reached"
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
    ["s_expiry"] = expiry
});


// ======================================================
// BUILD ACCOUNTS OUTPUT
// ======================================================

JsonObject? accountsNode = userNode["accounts"] as JsonObject;
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

    int remain = 3;

    if (node?["attempt_remaining"] != null)
    {
        if (node["attempt_remaining"] is JsonValue v)
        {
            if (!v.TryGetValue<int>(out remain))
            {
                int.TryParse(v.ToString(), out remain);
            }
        }
    }

    remain--;

    if (remain <= 0)
    {
        await PutJson($"{baseUrl}/hwid_attempts/{hwid}.json", new JsonObject
        {
            ["banned"] = true,
            ["banned_until"] = now + 86400,
            ["attempt_remaining"] = 0
        });

        return 0;
    }

    await PutJson($"{baseUrl}/hwid_attempts/{hwid}.json", new JsonObject
    {
        ["banned"] = false,
        ["banned_until"] = 0,
        ["attempt_remaining"] = remain
    });

    return remain;
}

app.Run();
