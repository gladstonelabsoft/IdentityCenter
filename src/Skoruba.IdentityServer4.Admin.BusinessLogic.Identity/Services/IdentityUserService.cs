
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Identity.Dtos.User;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Identity.Services.Interfaces;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Shared.Services;

namespace Skoruba.IdentityServer4.Admin.BusinessLogic.Identity.Services
{
    public class IdentityUserService : IIdentityUserService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ISecurePasswordService _securePasswordService;

        public IdentityUserService(UserManager<IdentityUser> userManager, ISecurePasswordService securePasswordService)
        {
            _userManager = userManager;
            _securePasswordService = securePasswordService;
        }

        public async Task<IdentityUserDto> ResetUserPasswordAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return null;

            var newPassword = _securePasswordService.GenerateSecurePassword();
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);

            if (!result.Succeeded)
            {
                throw new InvalidOperationException("Failed to reset password");
            }

            return new IdentityUserDto
            {
                Email = user.Email,
                UserName = user.UserName,
                TempPassword = newPassword
            };
        }
    }
}
