using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace STS.Configuration
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> Ids =>
        new List<IdentityResource>
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email()
            
        };

        public static IEnumerable<ApiResource> Apis =>
        new List<ApiResource>
        {
            new ApiResource
            {
                Name = "JSR",
                DisplayName = "JSR API",
                ApiSecrets = { new Secret("secret") },
                UserClaims = {JwtClaimTypes.Name,JwtClaimTypes.Email},
                Scopes =
                {
                    new Scope()
                    {
                        Name = "JSR.full_access",
                        DisplayName = "Full access to JSR",
                    },
                    new Scope
                    {
                        Name = "JSR.read_only",
                        DisplayName = "Read only access JSR"
                    }
                },
            }
        };
        public static IEnumerable<Client> Clients =>
            new List<Client>
            {
                  new Client
                    {
                        ClientId = "ConsoleClient",

                        // no interactive user, use the clientid/secret for authentication
                        AllowedGrantTypes = GrantTypes.ClientCredentials,

                        // secret for authentication
                        ClientSecrets = { new Secret("ConsoleClient".Sha256()) },

                        // scopes that client has access to
                        AllowedScopes = { "JSR" }
                    },
                  new Client
                    {
                        ClientId = "WebMVC",
                        ClientName = "WebMVC",
                        ClientSecrets = { new Secret("WebMVC".Sha256()) },
                        ClientUri = "http://localhost:5002",

                        AllowedGrantTypes = GrantTypes.Code,
                        RequirePkce = true,
                        RequireConsent = false,

                        AlwaysIncludeUserClaimsInIdToken = true,
                        AllowAccessTokensViaBrowser = false,

                        // where to redirect to after login
                        RedirectUris = { "http://localhost:5002/signin-oidc" },
                        // where to redirect to after logout
                        PostLogoutRedirectUris = { "http://localhost:5002/signout-callback-oidc" },
                        FrontChannelLogoutUri = "https://localhost:5002/signout-oidc",
                        AllowedScopes = new List<string>
                        {
                            IdentityServerConstants.StandardScopes.OpenId,
                            IdentityServerConstants.StandardScopes.Profile,
                            IdentityServerConstants.StandardScopes.Email,
                            "JSR",
                            "JSR.full_access"
                        },

                        AllowOfflineAccess = true,
                        AccessTokenLifetime = 60*60*2, // 2 hours
                        IdentityTokenLifetime= 60*60*2 // 2 hours
                    }
            };

    }
}