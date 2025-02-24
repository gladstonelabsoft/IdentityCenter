
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace Skoruba.IdentityServer4.Admin.BusinessLogic.Shared.Services
{
    public class SecurePasswordService : ISecurePasswordService
    {
        private const int PasswordLength = 16;
        private readonly PasswordHasher<string> _passwordHasher;

        public SecurePasswordService()
        {
            _passwordHasher = new PasswordHasher<string>();
        }

        public string GenerateSecurePassword()
        {
            using var rng = new RNGCryptoServiceProvider();
            var bytes = new byte[PasswordLength];
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        public Task<string> HashPasswordAsync(string password)
        {
            return Task.FromResult(_passwordHasher.HashPassword(null, password));
        }
    }
}
