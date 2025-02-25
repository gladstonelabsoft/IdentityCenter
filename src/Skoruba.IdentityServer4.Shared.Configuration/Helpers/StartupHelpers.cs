using System;
using Azure.Identity;
using Labsoft.Notification.Center.Contracts;
using MassTransit;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.UI.Services;
using Azure.Core;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SendGrid;
using Skoruba.IdentityServer4.Shared.Configuration.Configuration.Common;
using Skoruba.IdentityServer4.Shared.Configuration.Configuration.Email;
using Skoruba.IdentityServer4.Shared.Configuration.Email;
using Skoruba.IdentityServer4.Shared.Configuration.Services;
using Skoruba.IdentityServer4.Shared.Configuration.Services.Interfaces;

namespace Skoruba.IdentityServer4.Shared.Configuration.Helpers
{
    public static class StartupHelpers
    {
        /// <summary>
        /// Add email senders - configuration of sendgrid, smtp senders
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        public static void AddEmailSenders(this IServiceCollection services, IConfiguration configuration)
        {
            var smtpConfiguration = configuration.GetSection(nameof(SmtpConfiguration)).Get<SmtpConfiguration>();
            var sendGridConfiguration = configuration.GetSection(nameof(SendGridConfiguration)).Get<SendGridConfiguration>();
            var notificationCenterConfiguration = configuration.GetSection(nameof(NotificationCenterConfiguration)).Get<NotificationCenterConfiguration>();

            if (sendGridConfiguration != null && !string.IsNullOrWhiteSpace(sendGridConfiguration.ApiKey))
            {
                services.AddSingleton<ISendGridClient>(_ => new SendGridClient(sendGridConfiguration.ApiKey));
                services.AddSingleton(sendGridConfiguration);
                services.AddTransient<IEmailSender, SendGridEmailSender>();
            }
            else if (smtpConfiguration != null && !string.IsNullOrWhiteSpace(smtpConfiguration.Host))
            {
                services.AddSingleton(smtpConfiguration);
                services.AddTransient<IEmailSender, SmtpEmailSender>();
            }
            else if (notificationCenterConfiguration != null && !string.IsNullOrWhiteSpace(notificationCenterConfiguration.FromEmailAddress))
            {
                services.AddSingleton(notificationCenterConfiguration);
                services.AddTransient<IEmailSender, NotificationCenterEmailSender>();
                services.AddScoped<IQueueService, AzureServiceBusQueueService>();
            }
            else
            {
                services.AddSingleton<IEmailSender, LogEmailSender>();
            }
        }

        public static void AddDataProtection<TDbContext>(this IServiceCollection services, IConfiguration configuration)
                    where TDbContext : DbContext, IDataProtectionKeyContext
        {
            AddDataProtection<TDbContext>(
                services,
                configuration.GetSection(nameof(DataProtectionConfiguration)).Get<DataProtectionConfiguration>(),
                configuration.GetSection(nameof(AzureKeyVaultConfiguration)).Get<AzureKeyVaultConfiguration>());
        }

        public static void AddDataProtection<TDbContext>(this IServiceCollection services, DataProtectionConfiguration dataProtectionConfiguration, AzureKeyVaultConfiguration azureKeyVaultConfiguration)
            where TDbContext : DbContext, IDataProtectionKeyContext
        {
            var dataProtectionBuilder = services.AddDataProtection()
                .SetApplicationName("Skoruba.IdentityServer4")
                .PersistKeysToDbContext<TDbContext>();

            if (dataProtectionConfiguration.ProtectKeysWithAzureKeyVault)
            {
                if (azureKeyVaultConfiguration.UseClientCredentials)
                {
                    dataProtectionBuilder.ProtectKeysWithAzureKeyVault(
                        new Uri(azureKeyVaultConfiguration.DataProtectionKeyIdentifier),
                        new ClientSecretCredential(azureKeyVaultConfiguration.TenantId,
                            azureKeyVaultConfiguration.ClientId, azureKeyVaultConfiguration.ClientSecret));
                }
                else
                {
                    dataProtectionBuilder.ProtectKeysWithAzureKeyVault(new Uri(azureKeyVaultConfiguration.DataProtectionKeyIdentifier), new DefaultAzureCredential());
                }
            }
        }

        public static void AddAzureKeyVaultConfiguration(this IConfiguration configuration, IConfigurationBuilder configurationBuilder)
        {
            if (configuration.GetSection(nameof(AzureKeyVaultConfiguration)).Exists())
            {
                var azureKeyVaultConfiguration = configuration.GetSection(nameof(AzureKeyVaultConfiguration)).Get<AzureKeyVaultConfiguration>();

                if (azureKeyVaultConfiguration.ReadConfigurationFromKeyVault)
                {
                    TokenCredential credential = azureKeyVaultConfiguration.UseClientCredentials
                        ? new ClientSecretCredential(
                            azureKeyVaultConfiguration.TenantId,
                            azureKeyVaultConfiguration.ClientId,
                            azureKeyVaultConfiguration.ClientSecret)
                        : new DefaultAzureCredential();

                    configurationBuilder.AddAzureKeyVault(
                        new Uri(azureKeyVaultConfiguration.AzureKeyVaultEndpoint),
                        credential,
                        new AzureKeyVaultConfigurationOptions());
                }
            }
        }
    }
}
