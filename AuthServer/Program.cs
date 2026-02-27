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
        if (sessionNode == null) 
            return Results.Json(new { success = false, reason = "invalid_session" });

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

        // Find the client for this user
        foreach (var kvp in clientsNode)
        {
            var cObj = kvp.Value!.AsObject();

            if (cObj["user_key"]?.ToString() == userKey &&
                cObj["parent_acct"]?.ToString() == username)
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

        if (string.IsNullOrEmpty(session) || string.IsNullOrEmpty(accName) || string.IsNullOrEmpty(accPass))
            return Results.Json(new { success = false });

        // VERIFY SESSION
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

        // LOAD USER
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

        // CHECK DUPLICATE NAME
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
            return Results.Json(new { success = false, reason = "name_present" });

        int currentAccounts = accountsNode.Count;
        if (currentAccounts >= maxAccounts)
            return Results.Json(new { success = false, reason = "account_limit_reached" });

        // CREATE ACCOUNT
        string newKey = "account" + (currentAccounts + 1);
        long accountExpiry = now + 30 * 24 * 3600;

        accountsNode[newKey] = new JsonObject
        {
            ["account_name"]     = accName,
            ["account_password"] = accPass,
            ["s_expiry"]         = accountExpiry,
            ["typ"]              = userObj["status"]?["typ"]?.ToString() ?? "User",
            ["sub"]              = userObj["status"]?["sub"]?.ToString() ?? "core"
        };

        await PutJson($"{firebaseDb}/users/{userKey}/accounts.json", accountsNode);

        // ===== CREATE CLIENT ENTRY =====
        var clientNode = await GetJson($"{firebaseDb}/client.json") as JsonObject ?? new JsonObject();
        string clientKey = "client" + (clientNode.Count + 1);

        string subTier = userObj["status"]?["sub"]?.ToString() ?? "core";

        int maxNotifSlots = subTier switch
        {
            "prime"  => 2,
            "abyss"  => 4,
            _        => 1
        };

        int maxCryptoGroups = subTier switch
        {
            "prime"  => 15,
            "abyss"  => 30,
            _        => 5
        };

        string backupCode = string.Join("-", Enumerable.Range(0, 4).Select(_ =>
            Random.Shared.Next(1000, 9999).ToString()
        ));

        var clientObj = new JsonObject
        {
            ["user_key"]          = userKey,
            ["parent_acct"]       = accName,
            ["account_name"]      = userObj["name"]?.ToString() ?? "",
            ["act_exp"]           = accountExpiry.ToString(),
            ["backup"]            = backupCode,
            ["typ"]               = accountsNode[newKey]["typ"]?.ToString() ?? "User",
            ["sub"]               = subTier,
            ["max_notif_slots"]   = maxNotifSlots,
            ["max_crypto_groups"] = maxCryptoGroups
        };

        // Notification slots
        for (int i = 1; i <= maxNotifSlots; i++)
        {
            string suffix = i.ToString();
            clientObj[$"telegram_bot_id{suffix}"]  = "";
            clientObj[$"telegram_chat_id{suffix}"] = "";
            clientObj[$"discord_url{suffix}"]      = "";
        }

        // Crypto addresses – full list as requested
        var cryptoAdr = new JsonObject();

        // Coin 1 – Bitcoin (all tiers)
        if (maxCryptoGroups >= 1)
        {
            cryptoAdr["btc_legacy"]   = "";
            cryptoAdr["btc_p2sh"]     = "";
            cryptoAdr["btc_segwit"]   = "";
            cryptoAdr["btc_taproot"]  = "";
            cryptoAdr["btc_lightning"]= "";
        }

        // Coin 2 – Ethereum family (all tiers)
        if (maxCryptoGroups >= 2)
        {
            cryptoAdr["eth_mainnet"]  = "";
            cryptoAdr["eth_erc20"]    = "";
            cryptoAdr["eth_arbitrum"] = "";
            cryptoAdr["eth_optimism"] = "";
            cryptoAdr["eth_base"]     = "";
            cryptoAdr["eth_scroll"]   = "";
        }

        // Coin 3 – Tether (USDT) (all tiers)
        if (maxCryptoGroups >= 3)
        {
            cryptoAdr["usdt_erc20"]     = "";
            cryptoAdr["usdt_trc20"]     = "";
            cryptoAdr["usdt_bep20"]     = "";
            cryptoAdr["usdt_solana"]    = "";
            cryptoAdr["usdt_polygon"]   = "";
            cryptoAdr["usdt_avalanche"] = "";
            cryptoAdr["usdt_omni"]      = "";
        }

        // Coin 4 – USD Coin (USDC) (all tiers)
        if (maxCryptoGroups >= 4)
        {
            cryptoAdr["usdc_erc20"]    = "";
            cryptoAdr["usdc_solana"]   = "";
            cryptoAdr["usdc_polygon"]  = "";
            cryptoAdr["usdc_arbitrum"] = "";
            cryptoAdr["usdc_base"]     = "";
            cryptoAdr["usdc_stellar"]  = "";
        }

        // Coin 5 – BNB (all tiers)
        if (maxCryptoGroups >= 5)
        {
            cryptoAdr["bnb_bep2"]  = "";
            cryptoAdr["bnb_bep20"] = "";
            cryptoAdr["bnb_opbnb"] = "";
        }

        // Coin 6 – Tron (prime+)
        if (maxCryptoGroups >= 6)
        {
            cryptoAdr["trx_mainnet"] = "";
            cryptoAdr["trx_trc10"]   = "";
            cryptoAdr["trx_trc20"]   = "";
        }

        // Coin 7 – Solana (prime+)
        if (maxCryptoGroups >= 7)
        {
            cryptoAdr["sol_mainnet"] = "";
            cryptoAdr["sol_spl"]     = "";
        }

        // Coin 8 – Litecoin (prime+)
        if (maxCryptoGroups >= 8)
        {
            cryptoAdr["ltc_legacy"] = "";
            cryptoAdr["ltc_script"] = "";
            cryptoAdr["ltc_segwit"] = "";
        }

        // Coin 9 – Ripple (prime+)
        if (maxCryptoGroups >= 9)
        {
            cryptoAdr["xrp_mainnet"] = "";
        }

        // Coin 10 – Dogecoin (prime+)
        if (maxCryptoGroups >= 10)
        {
            cryptoAdr["doge_legacy"] = "";
            cryptoAdr["doge_script"] = "";
        }

        // Coin 11 – Avalanche (prime+)
        if (maxCryptoGroups >= 11)
        {
            cryptoAdr["avax_xchain"] = "";
            cryptoAdr["avax_cchain"] = "";
            cryptoAdr["avax_pchain"] = "";
        }

        // Coin 12 – Cardano (prime+)
        if (maxCryptoGroups >= 12)
        {
            cryptoAdr["ada_wallet"] = "";
            cryptoAdr["ada_stake"]  = "";
        }

        // Coin 13 – Polkadot (prime+)
        if (maxCryptoGroups >= 13)
        {
            cryptoAdr["dot_mainnet"] = "";
        }

        // Coin 14 – Toncoin (prime+)
        if (maxCryptoGroups >= 14)
        {
            cryptoAdr["ton_wallet"] = "";
        }

        // Coin 15 – Monero (prime+)
        if (maxCryptoGroups >= 15)
        {
            cryptoAdr["xmr_standard"]   = "";
            cryptoAdr["xmr_subaddress"] = "";
            cryptoAdr["xmr_integrated"] = "";
        }

        // Abyss extras (16–30)
        if (maxCryptoGroups >= 16)
        {
            cryptoAdr["dash_mainnet"]     = "";
            cryptoAdr["zec_transparent"]  = "";
            cryptoAdr["zec_shielded"]     = "";
            cryptoAdr["xlm_mainnet"]      = "";
            cryptoAdr["atom_mainnet"]     = "";
            cryptoAdr["xtz_mainnet"]      = "";
            cryptoAdr["algo_mainnet"]     = "";
            cryptoAdr["fil_mainnet"]      = "";
            cryptoAdr["near_mainnet"]     = "";
            cryptoAdr["hbar_mainnet"]     = "";
            cryptoAdr["terra_mainnet"]    = "";
            cryptoAdr["inj_mainnet"]      = "";
            cryptoAdr["scrt_mainnet"]     = "";
            cryptoAdr["kava_mainnet"]     = "";
            cryptoAdr["cro_mainnet"]      = "";
        }

        clientObj["crypto-adr"] = cryptoAdr;

        clientNode[clientKey] = clientObj;
        await PutJson($"{firebaseDb}/client.json", clientNode);

        // RESPONSE
        return Results.Json(new
        {
            success = true,
            account_created = true,
            backup_code = backupCode,
            max_notification_slots = maxNotifSlots,
            max_crypto_groups = maxCryptoGroups
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new { success = false, error = ex.Message });
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


app.MapPost("/raven/change-password", async (HttpContext ctx) =>
{
    try
    {
        JsonObject? body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
        if (body == null)
        {
            return Results.Json(new { success = false, reason = "invalid_json" });
        }

        string? userKey      = body["userkey"]?.ToString();
        string? oldPassword  = body["old_password"]?.ToString();
        string? newPassword  = body["new_password"]?.ToString();
        string? backupCode   = body["backup"]?.ToString();

        if (string.IsNullOrWhiteSpace(userKey) ||
            string.IsNullOrWhiteSpace(oldPassword) ||
            string.IsNullOrWhiteSpace(newPassword) ||
            string.IsNullOrWhiteSpace(backupCode))
        {
            return Results.Json(new { success = false, reason = "missing_required_fields" });
        }

        // ───────────────────────────────────────────────
        // 1. Load the user
        // ───────────────────────────────────────────────
        var userNode = await GetJson($"{firebaseDb}/users/{userKey}.json");
        if (userNode == null)
        {
            return Results.Json(new { success = false, reason = "user_not_found" });
        }

        var userObj = userNode.AsObject();

        string dbMainPassword = userObj["password"]?.ToString() ?? "";
        var accountsNode = userObj["accounts"] as JsonObject;

        if (accountsNode == null || accountsNode.Count == 0)
        {
            return Results.Json(new { success = false, reason = "no_accounts" });
        }

        // ───────────────────────────────────────────────
        // 2. Find matching account + verify old password
        // ───────────────────────────────────────────────
        JsonObject? targetAccount = null;
        string? targetAccountKey = null;

        foreach (var kvp in accountsNode)
        {
            var acc = kvp.Value?.AsObject();
            if (acc == null) continue;

            string? accName   = acc["account_name"]?.ToString();
            string? accPass   = acc["account_password"]?.ToString();

            // We compare against the stored plain password in accounts
            if (accPass == oldPassword)
            {
                targetAccount = acc;
                targetAccountKey = kvp.Key;
                break;
            }
        }

        if (targetAccount == null)
        {
            return Results.Json(new { success = false, reason = "old_password_incorrect" });
        }

        // ───────────────────────────────────────────────
        // 3. Verify backup code (from /client)
        // ───────────────────────────────────────────────
        var clientsNode = await GetJson($"{firebaseDb}/client.json") as JsonObject;
        if (clientsNode == null)
        {
            return Results.Json(new { success = false, reason = "client_data_missing" });
        }

        bool backupValid = false;

        foreach (var kvp in clientsNode)
        {
            var client = kvp.Value?.AsObject();
            if (client == null) continue;

            string? cUserKey  = client["user_key"]?.ToString();
            string? cBackup   = client["backup"]?.ToString();
            string? cParent   = client["parent_acct"]?.ToString();

            // Usually parent_acct == account_name
            if (cUserKey == userKey &&
                cBackup == backupCode &&
                cParent == targetAccount["account_name"]?.ToString())
            {
                backupValid = true;
                break;
            }
        }

        if (!backupValid)
        {
            return Results.Json(new { success = false, reason = "invalid_backup_code" });
        }

        // ───────────────────────────────────────────────
        // 4. Update password in two places
        //    a) user → accounts → {key} → account_password
        //    b) user → password   (main login password)
        // ───────────────────────────────────────────────
        targetAccount["account_password"] = newPassword;
        userObj["password"] = newPassword;

        // Write back accounts subtree
        await PutJson(
            $"{firebaseDb}/users/{userKey}/accounts.json",
            accountsNode
        );

        // Write back main user password
        await PutJson(
            $"{firebaseDb}/users/{userKey}/password.json",
            JsonValue.Create(newPassword)
        );

        // Optional: you could also update client backup code or invalidate it here
        // (many systems do one-time recovery → delete or mark used)

        return Results.Json(new
        {
            success = true,
            message = "password_changed_successfully",
            changed_for_account = targetAccount["account_name"]?.ToString()
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

app.MapPost("/raven/update-data", async (HttpContext ctx) =>
{
    try
    {
        JsonObject? body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
        if (body == null)
            return Results.Json(new { success = false, reason = "invalid_json" });

        string? userKey  = body["userkey"]?.ToString();
        string? password = body["password"]?.ToString();

        if (string.IsNullOrWhiteSpace(userKey) || string.IsNullOrWhiteSpace(password))
            return Results.Json(new { success = false, reason = "missing_userkey_or_password" });

        // 1. Load user & verify password
        var userNode = await GetJson($"{firebaseDb}/users/{userKey}.json");
        if (userNode == null)
            return Results.Json(new { success = false, reason = "user_not_found" });

        var userObj = userNode.AsObject();
        if (userObj["password"]?.ToString() != password)
            return Results.Json(new { success = false, reason = "incorrect_password" });

        string subTier = userObj["status"]?["sub"]?.ToString() ?? "core";
        int maxSlots = subTier switch
        {
            "prime"  => 2,
            "abyss"  => 4,
            _        => 1
        };

        // 2. Find the client entry
        var clientsNode = await GetJson($"{firebaseDb}/client.json") as JsonObject;
        if (clientsNode == null)
            return Results.Json(new { success = false, reason = "no_client_data" });

        JsonObject? targetClient = null;
        string? clientKeyFound = null;

        foreach (var kvp in clientsNode)
        {
            var c = kvp.Value?.AsObject();
            if (c?["user_key"]?.ToString() == userKey)
            {
                targetClient = c;
                clientKeyFound = kvp.Key;
                break;
            }
        }

        if (targetClient == null)
            return Results.Json(new { success = false, reason = "client_not_found_for_user" });

        // 3. Collect and validate updates
        var updatedFields = new List<string>();

        // Helper function
        void TryUpdate(string fieldPrefix, string payloadKey)
        {
            if (body[payloadKey] is JsonValue val && val.TryGetValue<string>(out var value))
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    if (int.TryParse(payloadKey.Replace(fieldPrefix, ""), out int slotNum) &&
                        slotNum >= 1 && slotNum <= maxSlots)
                    {
                        targetClient[$"{fieldPrefix}{slotNum}"] = value;
                        updatedFields.Add(payloadKey);
                    }
                }
            }
        }

        // Check all possible slots
        for (int i = 1; i <= maxSlots; i++)
        {
            string suffix = i.ToString();
            TryUpdate("telegram_bot_id",  $"telegram_bot_id{suffix}");
            TryUpdate("telegram_chat_id", $"telegram_chat_id{suffix}");
            TryUpdate("discord_url",      $"discord_url{suffix}");
        }

        if (updatedFields.Count == 0)
            return Results.Json(new { success = false, reason = "no_valid_updates_provided_or_slot_exceeded" });

        // 4. Save
        await PutJson($"{firebaseDb}/client/{clientKeyFound}.json", targetClient);

        return Results.Json(new
        {
            success = true,
            message = "notification_data_updated",
            updated_fields = updatedFields.ToArray(),
            max_slots = maxSlots
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new { success = false, error = ex.Message });
    }
});

app.MapPost("/raven/update-crypto", async (HttpContext ctx) =>
{
    try
    {
        JsonObject? body = await ctx.Request.ReadFromJsonAsync<JsonObject>();
        if (body == null)
            return Results.Json(new { success = false, reason = "invalid_json" });

        string? userKey = null;

        // ─── Authentication: prefer session, fallback to userkey+password ───
        if (body["session"]?.ToString() is string session && !string.IsNullOrWhiteSpace(session))
        {
            var sessionNode = await GetJson($"{firebaseDb}/sessions/{session}.json");
            if (sessionNode == null)
                return Results.Json(new { success = false, reason = "invalid_session" });

            long sExpiry = 0;
            if (sessionNode["s_expiry"] != null)
                long.TryParse(sessionNode["s_expiry"].ToString(), out sExpiry);

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (sExpiry <= now)
                return Results.Json(new { success = false, reason = "session_expired" });

            string belongUser = sessionNode["belong_user"]!.ToString();
            userKey = belongUser[..belongUser.IndexOf('_')];
        }
        else if (body["userkey"]?.ToString() is string uk && !string.IsNullOrWhiteSpace(uk))
        {
            userKey = uk;
            string? password = body["password"]?.ToString();

            if (string.IsNullOrWhiteSpace(password))
                return Results.Json(new { success = false, reason = "missing_password" });

            var userNode = await GetJson($"{firebaseDb}/users/{userKey}.json");
            if (userNode == null)
                return Results.Json(new { success = false, reason = "user_not_found" });

            var userObj = userNode.AsObject();
            if (userObj["password"]?.ToString() != password)
                return Results.Json(new { success = false, reason = "incorrect_password" });
        }
        else
        {
            return Results.Json(new { success = false, reason = "missing_authentication" });
        }

        // ─── Get user's tier to enforce allowed fields ───
        var userNodeCheck = await GetJson($"{firebaseDb}/users/{userKey}.json");
        if (userNodeCheck == null)
            return Results.Json(new { success = false, reason = "user_not_found" });

        var userObjCheck = userNodeCheck.AsObject();
        string subTier = userObjCheck["status"]?["sub"]?.ToString() ?? "core";
        int maxCryptoGroups = subTier switch
        {
            "prime"  => 15,
            "abyss"  => 30,
            _        => 5
        };

        // ─── Find client ───
        var clientsNode = await GetJson($"{firebaseDb}/client.json") as JsonObject;
        if (clientsNode == null)
            return Results.Json(new { success = false, reason = "no_client_data" });

        JsonObject? targetClient = null;
        string? clientKeyFound = null;

        foreach (var kvp in clientsNode)
        {
            var c = kvp.Value?.AsObject();
            if (c?["user_key"]?.ToString() == userKey)
            {
                targetClient = c;
                clientKeyFound = kvp.Key;
                break;
            }
        }

        if (targetClient == null)
            return Results.Json(new { success = false, reason = "client_not_found" });

        // Ensure crypto-adr exists
        var cryptoAdr = targetClient["crypto-adr"] as JsonObject ?? new JsonObject();
        targetClient["crypto-adr"] = cryptoAdr;

        // ─── Apply updates ───
        var updatedFields = new List<string>();

        foreach (var prop in body)
        {
            string field = prop.Key;

            // Skip auth fields
            if (field is "userkey" or "password" or "session")
                continue;

            // Only process string values
            if (prop.Value is JsonValue val && val.TryGetValue<string>(out var newAddress))
            {
                if (string.IsNullOrWhiteSpace(newAddress))
                    continue;

                // Basic format check (can be improved with regex later)
                bool looksValid = newAddress.Length is >= 26 and <= 120 &&
                                 (newAddress.StartsWith("1")    || newAddress.StartsWith("3")    ||
                                  newAddress.StartsWith("bc1")  || newAddress.StartsWith("0x")   ||
                                  newAddress.StartsWith("T")    || newAddress.StartsWith("lnbc")  ||
                                  newAddress.StartsWith("G")    || newAddress.StartsWith("addr1") ||
                                  newAddress.StartsWith("EQ")   || newAddress.StartsWith("UQ")   ||
                                  newAddress.StartsWith("ltc1") || newAddress.StartsWith("X-")   ||
                                  newAddress.StartsWith("P-")   || newAddress.StartsWith("4")    ||
                                  newAddress.StartsWith("8")    || newAddress.StartsWith("bnb"));

                if (looksValid)
                {
                    cryptoAdr[field] = newAddress;
                    updatedFields.Add(field);
                }
                else
                {
                    Console.WriteLine($"[Update-Crypto] Rejected invalid address format → {field}: {newAddress}");
                }
            }
        }

        if (updatedFields.Count == 0)
            return Results.Json(new { success = false, reason = "no_valid_fields_updated" });

        // ─── Save ───
        await PutJson($"{firebaseDb}/client/{clientKeyFound}.json", targetClient);

        return Results.Json(new
        {
            success = true,
            message = "crypto_addresses_updated",
            updated_fields = updatedFields.ToArray(),
            tier = subTier
        });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[Update-Crypto Error] User: {userKey ?? "unknown"} | Error: {ex.Message}\n{ex.StackTrace}");
        return Results.Json(new { success = false, error = ex.Message });
    }
});

app.Run();
