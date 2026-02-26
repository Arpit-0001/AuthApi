using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Timers;
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

const string SECRET = "RAVEN_BY_MR_ARPIT_120";



string firebaseDb =
    Environment.GetEnvironmentVariable("FIREBASE_DB_URL")!
    .TrimEnd('/');


// Call this after app.Build() but before app.Run()
var cleanupTimer = new System.Timers.Timer(600000); // 10 minutes
cleanupTimer.Elapsed += async (sender, e) =>
{
    await CleanupExpiredAccountsAndSessions();
};
cleanupTimer.AutoReset = true;
cleanupTimer.Start();

async Task CleanupExpiredAccountsAndSessions()
{
    long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    // 1. Cleanup sessions
    var sessionsNode = await GetJson($"{firebaseDb}/sessions.json") as JsonObject;
    if (sessionsNode != null)
    {
        foreach (var kvp in sessionsNode)  // Use foreach over JsonObject
        {
            string sessionKey = kvp.Key;
            var sessionValue = kvp.Value;

            long expiry = 0;
            if (sessionValue?["s_expiry"] != null)
                long.TryParse(sessionValue["s_expiry"]!.ToString(), out expiry);

            if (expiry <= now)
            {
                await DeleteJson($"{firebaseDb}/sessions/{sessionKey}.json");
            }
        }
    }

    // 2. Cleanup expired accounts
    var usersNode = await GetJson($"{firebaseDb}/users.json") as JsonObject;
    if (usersNode != null)
    {
        foreach (var kvp in usersNode)  // Again, foreach over JsonObject
        {
            string uKey = kvp.Key;
            var userEntry = kvp.Value!;

            var accountsNode = userEntry["accounts"] as JsonObject;
            if (accountsNode != null)
            {
                foreach (var accKvp in accountsNode)  // JsonObject loop
                {
                    string accKey = accKvp.Key;
                    var accValue = accKvp.Value;
                    // You can now safely use accKey and accValue
                }
            }
        }
    }
}

// Delete helper
static async Task DeleteJson(string url)
{
    using HttpClient http = new();
    await http.DeleteAsync(url);
}


app.MapPost("/raven/client", async (HttpContext ctx) =>
{
    try
    {
        JsonObject? body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
        if (body == null)
            return Results.Json(new { success = false, reason = "invalid_json" });

        string session = body["session"]?.ToString() ?? "";
        string username = body["username"]?.ToString() ?? "";

        if (string.IsNullOrEmpty(session) || string.IsNullOrEmpty(username))
            return Results.Json(new { success = false, reason = "missing_parameters" });

        // Check session
        var sessionNode = await GetJson($"{firebaseDb}/sessions/{session}.json");
        if (sessionNode == null) return Results.Json(new { success = false, reason = "invalid_session" });

        long sExpiry = 0;
        if (sessionNode["s_expiry"] != null)
            long.TryParse(sessionNode["s_expiry"].ToString(), out sExpiry);

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (sExpiry <= now)
            return Results.Json(new { success = false, reason = "session_expired" });

        string belongUser = sessionNode["belong_user"]!.ToString();
        string userKey = belongUser[..belongUser.IndexOf('_')];

        // Load client nodes
        var clientsNode = await GetJson($"{firebaseDb}/client.json") as JsonObject;
        if (clientsNode == null)
            return Results.Json(new { success = false, reason = "no_clients" });

        foreach (var kvp in clientsNode)  // kvp is KeyValuePair<string, JsonNode?>
        {
            string cKey = kvp.Key;
            var cObj = kvp.Value!.AsObject(); // cast safely to JsonObject
        
            if (cObj["parent_acct"]?.ToString() == userKey &&
                cObj["account_name"]?.ToString() == username)
            {
                return Results.Json(new
                {
                    success = true,
                    client_details = cObj
                });
            }
        }

        return Results.Json(new { success = false, reason = "client_not_found" });
    }
    catch (Exception ex)
    {
        return Results.Json(new { success = false, error = ex.Message });
    }
});

app.MapGet("/", () => "Raven Auth Running");


// ======================================================
// POST /raven/auth
// ======================================================

// ======================================================
// POST /raven/create_account
// ======================================================

app.MapPost("/raven/create_account", async (HttpContext ctx) =>
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
            return Results.Json(new { success = false });
        }

        if (body == null)
            return Results.Json(new { success = false });

        string session = body["session"]?.ToString() ?? "";
        string accName = body["account_name"]?.ToString() ?? "";
        string accPass = body["account_password"]?.ToString() ?? "";

        if (session == "" || accName == "" || accPass == "")
        {
            return Results.Json(new { success = false });
        }

        // ===== VERIFY SESSION =====
        var sessionNode = await GetJson($"{firebaseDb}/sessions/{session}.json");
        if (sessionNode == null)
            return Results.Json(new { success = false, reason = "invalid_session" });

        long expiry = 0;
        if (sessionNode["s_expiry"] is JsonValue v)
        {
            if (!v.TryGetValue<long>(out expiry))
                long.TryParse(v.ToString(), out expiry);
        }

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (now > expiry)
            return Results.Json(new { success = false, reason = "session_expired" });

        string belong = sessionNode["belong_user"]!.ToString();
        string userKey = belong[..belong.IndexOf('_')];

        // ===== LOAD USER =====
        var userNode = await GetJson($"{firebaseDb}/users/{userKey}.json");
        if (userNode == null)
            return Results.Json(new { success = false });

        var userObj = userNode.AsObject();
        var accountsNode = userObj["accounts"] as JsonObject ?? new JsonObject();
        var status = userObj["status"]!.AsObject();

        int maxAccounts = 1;
        if (status["max_hwid"] is JsonValue mv)
        {
            if (!mv.TryGetValue<int>(out maxAccounts))
                int.TryParse(mv.ToString(), out maxAccounts);
        }

        // ===== CHECK FOR DUPLICATE NAME =====
        bool nameExists = false;
        foreach (var kvp in accountsNode)
        {
            var account = kvp.Value?.AsObject();
            if (account != null && account["account_name"]?.GetValue<string>() == accName)
            {
                nameExists = true;
                break;
            }
        }
        
        if (nameExists)
        {
            return Results.Json(new { success = false, reason = "name_present" });
        }

        int currentAccounts = accountsNode.Count;
        if (currentAccounts >= maxAccounts)
        {
            return Results.Json(new { success = false, reason = "account_limit_reached" });
        }

        // ===== CREATE ACCOUNT =====
        string newKey = "account" + (currentAccounts + 1);
        long accountExpiry = now + 30 * 24 * 3600; // Example: 30 days expiry
        accountsNode[newKey] = new JsonObject
        {
            ["account_name"] = accName,
            ["account_password"] = accPass,
            ["s_expiry"] = accountExpiry,
            ["typ"] = userObj["status"]?["typ"]?.ToString() ?? "User",
            ["sub"] = userObj["status"]?["sub"]?.ToString() ?? "core"
        };

        await PutJson($"{firebaseDb}/users/{userKey}/accounts.json", accountsNode);

        // ===== CREATE CLIENT ENTRY =====
        var clientNode = await GetJson($"{firebaseDb}/client.json") as JsonObject ?? new JsonObject();
        string clientKey = "client" + (clientNode.Count + 1);

        // Generate random backup code: XXXX-XXXX-XXXX-XXXX
        string backupCode = string.Join("-", Enumerable.Range(0, 4).Select(_ =>
            Random.Shared.Next(1000, 9999).ToString()
        ));

        clientNode[clientKey] = new JsonObject
        {
            ["parent_acct"] = accName,
            ["account_name"] = userObj["name"]?.ToString() ?? "",
            ["act_exp"] = accountExpiry.ToString(),
            ["backup"] = backupCode,
            ["typ"] = accountsNode[newKey]["typ"]?.ToString() ?? "User",
            ["sub"] = accountsNode[newKey]["sub"]?.ToString() ?? "core",
            ["telegram_bot_id"] = "",
            ["telegram_chat_id"] = "",
            ["discord_url"] = ""
        };

        await PutJson($"{firebaseDb}/client.json", clientNode);

        // ===== RESPONSE =====
        return Results.Json(new
        {
            success = true,
            account_created = true,
            backup_code = backupCode
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
    
    /* ---------- REGISTER HWID (FIXED LIMIT) ---------- */
    
    int maxHwid = 1;
    
    if (status["max_hwid"] is JsonValue mv)
    {
        if (!mv.TryGetValue<int>(out maxHwid))
            int.TryParse(mv.ToString(), out maxHwid);
    }
    
    if (!hwidLocked)
    {
        bool exists = hwidArray.Any(x => x?.ToString() == hwid);
    
        if (!exists)
        {
            int used = hwidArray.Count(x => !string.IsNullOrEmpty(x?.ToString()));
    
            if (used >= maxHwid)
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
    
            int emptyIndex = -1;
    
            for (int i = 0; i < hwidArray.Count; i++)
            {
                if (string.IsNullOrEmpty(hwidArray[i]?.ToString()))
                {
                    emptyIndex = i;
                    break;
                }
            }
    
            if (emptyIndex == -1)
            {
                hwidArray.Add(hwid);
            }
            else
            {
                hwidArray[emptyIndex] = hwid;
            }
    
            await PutJson(
                $"{firebaseDb}/users/{userKey}/status/hwids.json",
                hwidArray
            );
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
