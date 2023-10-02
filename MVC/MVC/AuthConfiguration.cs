using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text.Json;

namespace MVC
{
    internal static class AuthConfiguration
    {
        internal static void ConfigureOpenIdAuth(this WebApplicationBuilder builder)
        {
            builder.Services.AddTransient<IClaimsTransformation, KeycloakRolesClaimTransformer>();

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(cookie =>
            {
                cookie.Cookie.Name = "keycloakcookie";
                //cookie.Cookie.MaxAge = TimeSpan.FromMinutes(60);
                cookie.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                cookie.SlidingExpiration = true;
            })
            .AddOpenIdConnect(options =>
            {
                options.Authority = builder.Configuration.GetSection("Keycloak")["Authority"];
                options.ClientId = builder.Configuration.GetSection("Keycloak")["ClientId"];
                options.ClientSecret = builder.Configuration.GetSection("Keycloak")["ClientSecret"];
                options.ResponseType = "code";
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;
                options.RequireHttpsMetadata = false;
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.NonceCookie.SameSite = SameSiteMode.Unspecified;
                options.CorrelationCookie.SameSite = SameSiteMode.Unspecified;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "preferred_username",
                    //RoleClaimType = "roles",
                    ValidateIssuer = true
                };
            });
        }
    }

    internal class KeycloakRolesClaimTransformer : IClaimsTransformation
    {
        public IConfiguration _configuration;

        public KeycloakRolesClaimTransformer(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            ClaimsIdentity claimsIdentity = (ClaimsIdentity)principal.Identity;

            if (claimsIdentity.IsAuthenticated)
            {
                // We can hard-code the ClientId here, because otherwise we have to inject IConfiguration and retrieve this data every request.
                var clientId = _configuration.GetSection("Keycloak")["ClientId"];

                AddRolesToClaims(claimsIdentity, clientId);
            }

            return Task.FromResult(principal);
        }

        private static void AddRolesToClaims(ClaimsIdentity claimsIdentity, string clientId)
        {
            if (claimsIdentity.HasClaim((claim) => claim.Type == "resource_access"))
            {
                var resourceAccessClaim = claimsIdentity.FindFirst(claim => claim.Type == "resource_access");
                var resourceAccessJson = resourceAccessClaim.Value;

                if (!string.IsNullOrEmpty(resourceAccessJson))
                {
                    var resourceAccess = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, List<string>>>>(resourceAccessJson);

                    if (resourceAccess.ContainsKey(clientId))
                    {
                        var roles = resourceAccess[clientId]["roles"];

                        foreach (var role in roles)
                        {
                            claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, role));
                        }
                    }
                }
            }
        }

    }
}
