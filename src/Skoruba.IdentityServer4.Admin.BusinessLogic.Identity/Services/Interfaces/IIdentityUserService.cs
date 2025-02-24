
using System.Threading.Tasks;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Identity.Dtos.User;

namespace Skoruba.IdentityServer4.Admin.BusinessLogic.Identity.Services.Interfaces
{
    public interface IIdentityUserService
    {
        Task<IdentityUserDto> ResetUserPasswordAsync(string email);
    }
}
