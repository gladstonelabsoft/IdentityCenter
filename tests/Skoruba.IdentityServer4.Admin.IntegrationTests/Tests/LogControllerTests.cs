using AutoFixture;
using FluentAssertions;
using Moq;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Dtos.Log;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Services.Interfaces;
using Skoruba.IdentityServer4.Admin.IntegrationTests.Tests.Base;
using Skoruba.IdentityServer4.Admin.UI.Configuration.Constants;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace Skoruba.IdentityServer4.Admin.IntegrationTests.Tests
{
    public class LogControllerTests : BaseClassFixture
    {
        private readonly Mock<IAuditLogService> _auditLogService;
        private readonly Fixture _fixture;
        public LogControllerTests(TestFixture fixture) : base(fixture)
        {
            _auditLogService = new Mock<IAuditLogService>();
            _fixture = new Fixture();

        }

        [Fact]
        public async Task ReturnRedirectInErrorsLogWithoutAdminRole()
        {
            //Remove
            Client.DefaultRequestHeaders.Clear();

            // Act
            var response = await Client.GetAsync("/log/errorslog");

            // Assert           
            response.StatusCode.Should().Be(HttpStatusCode.Redirect);

            //The redirect to login
            response.Headers.Location.ToString().Should().Contain(AuthenticationConsts.AccountLoginPage);
        }

        [Fact]
        public async Task ReturnRedirectInAuditLogWithoutAdminRole()
        {
            //Remove
            Client.DefaultRequestHeaders.Clear();

            // Act
            var response = await Client.GetAsync("/log/auditlog");

            // Assert           
            response.StatusCode.Should().Be(HttpStatusCode.Redirect);

            //The redirect to login
            response.Headers.Location.ToString().Should().Contain(AuthenticationConsts.AccountLoginPage);
        }

        [Fact]
        public async Task ReturnSuccessInErrorsLogWithAdminRole()
        {
            SetupAdminClaimsViaHeaders();

            // Act
            var response = await Client.GetAsync("/log/errorslog");

            // Assert
            response.EnsureSuccessStatusCode();
            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task ReturnSuccessInAuditLogWithAdminRole()
        {
           SetupAdminClaimsViaHeaders();

            // Act
            var response = await Client.GetAsync("/log/auditlog");

            // Assert
            response.EnsureSuccessStatusCode();
            response.StatusCode.Should().Be(HttpStatusCode.OK);   
            
        }

        [Fact]
        public async Task GetAsync_ShouldReturnLogs()
        {
            // Arrange
            var logs = _fixture.Create<AuditLogsDto>();
            var filters = _fixture.Create<AuditLogFilterDto>();

            _auditLogService
                .Setup(x => x.GetAsync(It.IsAny<AuditLogFilterDto>()))
                .Returns(Task.FromResult(logs));

            var auditLogService = _auditLogService.Object;

            // Act
            var result = await auditLogService.GetAsync(filters);

            // Assert
            Assert.NotNull(result);
        }
    }
}

