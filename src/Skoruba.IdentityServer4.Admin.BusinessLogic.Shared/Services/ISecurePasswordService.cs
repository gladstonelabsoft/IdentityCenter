
using System.Threading.Tasks;

namespace Skoruba.IdentityServer4.Admin.BusinessLogic.Shared.Services
{
    public interface ISecurePasswordService
    {
        string GenerateSecurePassword();
        Task<string> HashPasswordAsync(string password);
    }
}
