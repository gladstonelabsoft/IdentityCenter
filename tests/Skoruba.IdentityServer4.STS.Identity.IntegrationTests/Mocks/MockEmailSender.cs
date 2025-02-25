using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace Skoruba.IdentityServer4.STS.Identity.IntegrationTests.Mocks
{
    public class MockEmailSender : IEmailSender
    {
        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            return Task.CompletedTask;
        }
    }
}
