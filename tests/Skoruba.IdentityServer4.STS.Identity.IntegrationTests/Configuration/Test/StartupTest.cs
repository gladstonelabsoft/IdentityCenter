using System;
using System.Collections.Generic;
using System.IO;
using IdentityServer4;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Skoruba.IdentityServer4.Admin.EntityFramework.Shared.DbContexts;
using Skoruba.IdentityServer4.Admin.EntityFramework.Shared.Entities.Identity;
using Skoruba.IdentityServer4.STS.Identity.Helpers;
using Skoruba.IdentityServer4.STS.Identity.Configuration;
using Skoruba.IdentityServer4.STS.Identity.Configuration.Constants;
using Skoruba.IdentityServer4.STS.Identity.Configuration.Interfaces;
using Skoruba.IdentityServer4.STS.Identity.Configuration.LogConfigurations;
using Skoruba.IdentityServer4.STS.Identity.IntegrationTests.Mocks;

namespace Skoruba.IdentityServer4.STS.Identity.IntegrationTests.Configuration.Test
{
    public class StartupTest : Startup
    {
        public StartupTest(IWebHostEnvironment env, IConfiguration configuration) : base(env, configuration)
        {
        }

        public override void ConfigureServices(IServiceCollection services)
        {
            var environment = Configuration["AspNet_Environment"] ?? string.Empty;
            LogConfiguration.AddSerilogLabsoftApplicationLog(services,
                Configuration,
                environment);

            var rootConfiguration = CreateRootConfiguration();
            services.AddSingleton(rootConfiguration);

            // Add DbContext
            RegisterDbContexts(services);

            // Add test-specific identity and IdentityServer configuration
            services.AddAuthenticationServices<AdminIdentityDbContext, UserIdentity, UserIdentityRole>(Configuration);

            // Add mock email sender for testing
            services.AddTransient<IEmailSender, MockEmailSender>();

            // Add IdentityServer with test configuration
            services.AddIdentityServer(options => {
                    options.EmitStaticAudienceClaim = true;
                    options.Authentication.CookieLifetime = TimeSpan.FromHours(1);
                    options.Authentication.CookieSlidingExpiration = true;
                })
                .AddInMemoryClients(TestClients.GetTestClients())
                .AddInMemoryApiScopes(new List<ApiScope> { new ApiScope("api1", "Test API") })
                .AddInMemoryIdentityResources(new List<IdentityResource> 
                {
                    new IdentityResources.OpenId(),
                    new IdentityResources.Profile(),
                    new IdentityResources.Email()
                })
                .AddDeveloperSigningCredential()
                .AddAspNetIdentity<UserIdentity>();

            // Configure external providers for testing
            services.Configure<ExternalProvidersConfiguration>(options =>
            {
                options.UseAzureAdProvider = true;
                options.AzureAdTenantId = "common";
                options.AzureAdClientId = "test-client";
                options.AzureAdSecret = "test-secret";
                options.AzureInstance = "https://login.microsoftonline.com/";
                options.AzureDomain = "test.onmicrosoft.com";
            });

            // Add MVC with localization
            services.AddMvcWithLocalization<UserIdentity, string>(Configuration);

            // Add health checks
            services.AddHealthChecks()
                .AddCheck<IdentityServerHealthCheck>("IdentityServer");

            // Add CORS policy for testing
            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy",
                    builder => builder.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader());
            });

            // Add MVC with views
            services.AddControllersWithViews()
                .AddApplicationPart(typeof(Skoruba.IdentityServer4.STS.Identity.Startup).Assembly);

            // Add Razor pages
            services.AddRazorPages();

            // Configure views to look in the main project's view directory
            services.Configure<Microsoft.AspNetCore.Mvc.Razor.RazorViewEngineOptions>(options =>
            {
                options.ViewLocationFormats.Clear();
                options.ViewLocationFormats.Add("/Views/{1}/{0}.cshtml");
                options.ViewLocationFormats.Add("/Views/Shared/{0}.cshtml");
                options.ViewLocationFormats.Add("/src/Skoruba.IdentityServer4.STS.Identity/Views/{1}/{0}.cshtml");
                options.ViewLocationFormats.Add("/src/Skoruba.IdentityServer4.STS.Identity/Views/Shared/{0}.cshtml");
            });

            // Add authorization
            RegisterAuthorization(services);
        }

        public override void RegisterDbContexts(IServiceCollection services)
        {
            services.RegisterDbContextsStaging<AdminIdentityDbContext, 
                IdentityServerConfigurationDbContext, 
                IdentityServerPersistedGrantDbContext, 
                IdentityServerDataProtectionDbContext,
                AdminLogDbContext>();
        }
    }
}
