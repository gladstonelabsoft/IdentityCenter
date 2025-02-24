using System.Diagnostics.CodeAnalysis;

namespace Skoruba.IdentityServer4.Admin.EntityFramework.Shared.Entities.Email
{
    [ExcludeFromCodeCoverage]
    public class EmailNotificationToSend
    {
        public string? FromEmailAddress { get; }
        public string? ToEmailAddress { get; }
        public string? Subject { get; }
        public string? TextContent { get; }
        public string? HtmlContent { get; }

        public EmailNotificationToSend(
            string? fromEmailAddress,
            string? toEmailAddress,
            string? subject,
            string? textContent,
            string? htmlContent)
        {
            FromEmailAddress = fromEmailAddress;
            ToEmailAddress = toEmailAddress;
            Subject = subject;
            TextContent = textContent;
            HtmlContent = htmlContent;
        }
    }
}
