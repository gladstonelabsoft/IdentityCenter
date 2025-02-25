using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Serilog.Exceptions;
using Serilog.Formatting.Json;
using Serilog.Sinks.RabbitMQ;
using System.Diagnostics.CodeAnalysis;

namespace Skoruba.IdentityServer4.Admin.Api.Configuration.LogConfigurations
{
    [ExcludeFromCodeCoverage]
    public static class LogConfiguration
    {
        public static void AddSerilogLabsoftApplicationLog(
            IServiceCollection services,
            IConfiguration configuration,
            string environment)
        {
            var logger = new LoggerConfiguration()
                .Enrich.FromLogContext()
                .Enrich.WithExceptionDetails()
                .Enrich.WithProperty("ApplicationName", "Labsoft.IdentityCenter.Api")
                .Enrich.WithProperty("Environment", environment)
                .MinimumLevel.Error()
                .WriteTo.Console()
                .CreateLogger();

            services.AddLogging(lb => lb.AddSerilog(logger));
        }
    }
}
