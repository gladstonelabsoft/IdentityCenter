
using System.ComponentModel.DataAnnotations;

namespace Skoruba.IdentityServer4.Admin.Api.Dtos.Users
{
    public class UserResetPasswordRequestDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
