using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using IdentityModel.Client;
using Skoruba.IdentityServer4.STS.Identity.IntegrationTests.Tests.Base;
using Xunit;

namespace Skoruba.IdentityServer4.STS.Identity.IntegrationTests.Tests
{
    public class IdentityServerTests : BaseClassFixture
    {
        public IdentityServerTests(TestFixture fixture) : base(fixture)
        {
        }

        [Fact]
        public async Task CanShowDiscoveryEndpoint()
        {
            var disco = await Client.GetDiscoveryDocumentAsync("http://localhost");

            disco.Should().NotBeNull();
            disco.IsError.Should().Be(false);

            disco.KeySet.Keys.Count.Should().Be(1);
        }

        [Fact]
        public async Task CanUseDefaultAuthenticationScheme()
        {
            var disco = await Client.GetDiscoveryDocumentAsync("http://localhost");
            disco.IsError.Should().Be(false);

            var response = await Client.RequestTokenAsync(new TokenRequest
            {
                Address = disco.TokenEndpoint,
                GrantType = "client_credentials",
                ClientId = "test-client",
                ClientSecret = "test-secret"
            });

            response.IsError.Should().Be(false);
            response.AccessToken.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task CanUseExternalAuthenticationScheme()
        {
            var disco = await Client.GetDiscoveryDocumentAsync("http://localhost");
            disco.IsError.Should().Be(false);

            var authorizeUrl = new RequestUrl(disco.AuthorizeEndpoint)
                .CreateAuthorizeUrl(
                    clientId: "test-client",
                    responseType: "code",
                    scope: "openid profile",
                    redirectUri: "http://localhost/callback",
                    state: "state",
                    nonce: "nonce",
                    extra: new Parameters(new Dictionary<string, string> { { "idp", "AzureAD" } })
                );

            authorizeUrl.Should().Contain("idp=AzureAD");
        }
    }
}
