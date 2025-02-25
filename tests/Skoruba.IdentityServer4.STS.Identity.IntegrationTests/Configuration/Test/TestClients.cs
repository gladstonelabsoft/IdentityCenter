using System;
using System.Collections.Generic;
using IdentityServer4.Models;

namespace Skoruba.IdentityServer4.STS.Identity.IntegrationTests.Configuration.Test
{
    public static class TestClients
    {
        public static IEnumerable<Client> GetTestClients()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientId = Environment.GetEnvironmentVariable("IDENTITY_TEST_CLIENT_ID") 
                        ?? throw new InvalidOperationException("Integration tests require IDENTITY_TEST_CLIENT_ID to be configured in environment"),
                    ClientSecrets = { new Secret(Environment.GetEnvironmentVariable("IDENTITY_TEST_CLIENT_SECRET") 
                        ?? throw new InvalidOperationException("Integration tests require IDENTITY_TEST_CLIENT_SECRET to be configured in environment")) },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes = { "openid", "profile", "api1" },
                    RequireClientSecret = true,
                    RequirePkce = false
                }
            };
        }
    }
}
