// Original file comes from: https://github.com/damienbod/IdentityServer4AspNetCoreIdentityTemplate
// Modified by Jan Škoruba

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Skoruba.IdentityServer4.Shared.Configuration.Configuration.Common;

namespace Skoruba.IdentityServer4.Shared.Configuration.Services
{
    public class AzureKeyVaultService
    {
        private readonly AzureKeyVaultConfiguration _azureKeyVaultConfiguration;

        public AzureKeyVaultService(AzureKeyVaultConfiguration azureKeyVaultConfiguration)
        {
            if (azureKeyVaultConfiguration == null)
            {
                throw new ArgumentException("missing azureKeyVaultConfiguration");
            }

            if (string.IsNullOrEmpty(azureKeyVaultConfiguration.AzureKeyVaultEndpoint))
            {
                throw new ArgumentException("missing keyVaultEndpoint");
            }

            _azureKeyVaultConfiguration = azureKeyVaultConfiguration;
        }

        public async Task<(X509Certificate2 ActiveCertificate, X509Certificate2 SecondaryCertificate)> GetCertificatesFromKeyVault()
        {
            (X509Certificate2 ActiveCertificate, X509Certificate2 SecondaryCertificate) certs = (null, null);

            var credential = GetCredential();
            var vaultUri = new Uri(_azureKeyVaultConfiguration.AzureKeyVaultEndpoint);
            var certificateClient = new CertificateClient(vaultUri, credential);
            var secretClient = new SecretClient(vaultUri, credential);

            var certificateItems = await GetAllEnabledCertificateVersionsAsync(certificateClient);
            var item = certificateItems.FirstOrDefault();
            if (item != null)
            {
                certs.ActiveCertificate = await GetCertificateAsync(item.Id, secretClient);
            }

            if (certificateItems.Count > 1)
            {
                certs.SecondaryCertificate = await GetCertificateAsync(certificateItems[1].Id, secretClient);
            }

            return certs;
        }

        private TokenCredential GetCredential()
        {
            if (_azureKeyVaultConfiguration.UseClientCredentials)
            {
                return new ClientSecretCredential(
                    tenantId: _azureKeyVaultConfiguration.TenantId,
                    clientId: _azureKeyVaultConfiguration.ClientId,
                    clientSecret: _azureKeyVaultConfiguration.ClientSecret);
            }

            return new DefaultAzureCredential();
        }

        private async Task<List<CertificateProperties>> GetAllEnabledCertificateVersionsAsync(CertificateClient certificateClient)
        {
            // Get all the certificate versions
            var certificateVersions = await Task.Run(() => certificateClient.GetPropertiesOfCertificateVersions(_azureKeyVaultConfiguration.IdentityServerCertificateName));

            // Find all enabled versions of the certificate and sort them by creation date in descending order
            return certificateVersions
                .Where(certVersion => certVersion.Enabled.HasValue && certVersion.Enabled.Value)
                .OrderByDescending(certVersion => certVersion.CreatedOn)
                .ToList();
        }

        private async Task<X509Certificate2> GetCertificateAsync(Uri identifier, SecretClient secretClient)
        {
            var secret = await secretClient.GetSecretAsync(identifier.ToString());
            var privateKeyBytes = Convert.FromBase64String(secret.Value.Value);
            var certificateWithPrivateKey = new X509Certificate2(privateKeyBytes, (string)null, X509KeyStorageFlags.MachineKeySet);

            return certificateWithPrivateKey;
        }
    }
}
