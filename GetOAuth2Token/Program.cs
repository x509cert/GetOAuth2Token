using Azure.Core;
using Azure.Identity;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text.Json;

var credential = new AzureCliCredential();

string audAkv = "https://vault.azure.net";
var tokenRequestContextAkv = new TokenRequestContext([audAkv]);
var accessTokenAkv = await credential.GetTokenAsync(tokenRequestContextAkv);
ParseAndDumpJwtToken(accessTokenAkv.Token, audAkv);

string audSql = "https://database.windows.net";
var tokenRequestContextSql = new TokenRequestContext([audSql]);
var accessTokenSql = await credential.GetTokenAsync(tokenRequestContextSql);
ParseAndDumpJwtToken(accessTokenSql.Token, audSql);

static bool IsJwtTokenValid(string token, string aud, string tid) {
    var handler = new JsonWebTokenHandler();
    var tokenValidationParameters = new TokenValidationParameters {
        
        ValidAudience = aud,
        ValidateAudience = true, 
        ValidateLifetime = true,
        ValidateIssuer = true,
        ValidIssuer = $"https://sts.windows.net/{tid}/",
        ValidateIssuerSigningKey = true,
        
        IssuerSigningKeyResolver = (token, securityToken, kid, parameters) => {
            var jwksUrl = $"https://login.microsoftonline.com/{tid}/discovery/v2.0/keys";

            using var httpClient = new HttpClient();
            var response = httpClient.GetStringAsync(jwksUrl).Result;
            using var jsonDoc = JsonDocument.Parse(response);
            var keys = jsonDoc.RootElement.GetProperty("keys").EnumerateArray();
            foreach (var key in keys) {
                if (key.GetProperty("kid").GetString() == kid) {
                    var jsonWebKey = new JsonWebKey(key.GetRawText());
                    return [jsonWebKey];
                }
            }

            return null; 
        }
    };

    var validationResult = handler.ValidateToken(token, tokenValidationParameters);
    return validationResult.IsValid;
}
static void ParseAndDumpJwtToken(string token, string aud) {

    Console.WriteLine($"\nToken: {token}\n");

    var handler = new JsonWebTokenHandler();
    var jsonToken = handler.ReadJsonWebToken(token);
    var tid = jsonToken.Claims.First(c => c.Type == "tid").Value;
    var usedMfa = jsonToken.Claims.FirstOrDefault(claim => claim.Type == "amr" && claim.Value.Contains("mfa")) != null;

    Console.WriteLine($"Used MFA?: {usedMfa}");
    Console.WriteLine($"Is Valid : {IsJwtTokenValid(token, aud, tid)}");
    Console.WriteLine($"Audience : {jsonToken.Audiences.First()}");
    Console.WriteLine($"Issuer   : {jsonToken.Issuer}");
    Console.WriteLine($"Signed   : {jsonToken.IsSigned}");
    Console.WriteLine($"Signature: {jsonToken.EncodedSignature}");

    foreach (var claim in jsonToken.Claims) {
        Console.WriteLine($"{claim.Type}: {claim.Value}");
    }

    if (jsonToken.ValidTo != DateTime.MinValue) {
        Console.WriteLine($"Expiry: {jsonToken.ValidTo}");
    }
}

