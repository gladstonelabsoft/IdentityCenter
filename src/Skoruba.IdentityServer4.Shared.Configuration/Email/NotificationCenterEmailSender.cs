using IdentityServer4.Models;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Skoruba.IdentityServer4.Admin.EntityFramework.Shared.Entities.Email;
using Skoruba.IdentityServer4.Shared.Configuration.Configuration.Email;
using Skoruba.IdentityServer4.Shared.Configuration.Services.Interfaces;
using System;
using System.Threading.Tasks;

namespace Skoruba.IdentityServer4.Shared.Configuration.Email
{
    public class NotificationCenterEmailSender : IEmailSender
    {
        private readonly ILogger<LogEmailSender> _logger;
        private readonly NotificationCenterConfiguration _notificationCenterConfiguration;
        private readonly IHttpRequestService _httpRequestService;

        public NotificationCenterEmailSender(
            ILogger<LogEmailSender> logger, 
            NotificationCenterConfiguration notificationCenterConfiguration,
            IHttpRequestService httpRequestService)
        {
            _logger = logger;
            _notificationCenterConfiguration = notificationCenterConfiguration;
            _httpRequestService = httpRequestService;
        }

        public async Task SendEmailAsync(
            string email, 
            string subject, 
            string htmlMessage)
        {
            try
            {
                var emailNotificationToSend = new EmailNotificationToSend(
                    fromEmailAddress: _notificationCenterConfiguration.FromEmailAddress,
                    toEmailAddress: email,
                    subject: subject,
                    textContent: string.Empty,
                    htmlContent: htmlMessage);

                var token = await GetNotificationCenterToken();

                await _httpRequestService.PostAsync(
                     requestUri: _notificationCenterConfiguration.LabsoftNotificationCenterApi,
                     objectBody: JsonConvert.SerializeObject(emailNotificationToSend),
                     token);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Exception {ex} during sending email: {email}, subject: {subject}");
                throw;
            }
        }
        private async Task<string> GetNotificationCenterToken()
        {
            var result = await _httpRequestService.PostFormAsync
                (_notificationCenterConfiguration.AuthUrl,
                _notificationCenterConfiguration.LabsoftNotificationCenterClientId,
                _notificationCenterConfiguration.LabsoftNotificationCenterScope,
                _notificationCenterConfiguration.LabsoftNotificationCenterClientSecret,
                GrantType.ClientCredentials,
                "");

            var parsedObject = JObject.Parse(result.Content);
            var token = parsedObject?["access_token"]?.ToString() ?? string.Empty;

            return token;
        }
    }
}