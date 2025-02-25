using System.Collections.Generic;
using System.Linq;
using AutoMapper;
using IdentityServer4.EntityFramework.Entities;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Dtos.Configuration;

namespace Skoruba.IdentityServer4.Admin.BusinessLogic.Mappers.Converters
{
    public class ClientCollectionTypeConverter : ITypeConverter<Client, ClientDto>, ITypeConverter<ClientDto, Client>
    {
        public ClientDto Convert(Client source, ClientDto destination, ResolutionContext context)
        {
            if (destination == null) destination = new ClientDto();

            destination.PostLogoutRedirectUris = source?.PostLogoutRedirectUris?.Select(x => x.PostLogoutRedirectUri).ToList() ?? new List<string>();
            destination.RedirectUris = source?.RedirectUris?.Select(x => x.RedirectUri).ToList() ?? new List<string>();
            destination.AllowedScopes = source?.AllowedScopes?.Select(x => x.Scope).ToList() ?? new List<string>();
            destination.AllowedGrantTypes = source?.AllowedGrantTypes?.Select(x => x.GrantType).ToList() ?? new List<string>();
            destination.Properties = source?.Properties?.Select(x => context.Mapper.Map<ClientPropertyDto>(x)).ToList() ?? new List<ClientPropertyDto>();
            destination.Claims = source?.Claims?.Select(x => context.Mapper.Map<ClientClaimDto>(x)).ToList() ?? new List<ClientClaimDto>();
            destination.IdentityProviderRestrictions = source?.IdentityProviderRestrictions?.Select(x => x.Provider).ToList() ?? new List<string>();
            destination.AllowedCorsOrigins = source?.AllowedCorsOrigins?.Select(x => x.Origin).ToList() ?? new List<string>();

            return destination;
        }

        public Client Convert(ClientDto source, Client destination, ResolutionContext context)
        {
            if (destination == null) destination = new Client();

            destination.PostLogoutRedirectUris = source?.PostLogoutRedirectUris?.Select(x => new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = x }).ToList() ?? new List<ClientPostLogoutRedirectUri>();
            destination.RedirectUris = source?.RedirectUris?.Select(x => new ClientRedirectUri { RedirectUri = x }).ToList() ?? new List<ClientRedirectUri>();
            destination.AllowedScopes = source?.AllowedScopes?.Select(x => new ClientScope { Scope = x }).ToList() ?? new List<ClientScope>();
            destination.AllowedGrantTypes = source?.AllowedGrantTypes?.Select(x => new ClientGrantType { GrantType = x }).ToList() ?? new List<ClientGrantType>();
            destination.Properties = source?.Properties?.Select(x => context.Mapper.Map<ClientProperty>(x)).ToList() ?? new List<ClientProperty>();
            destination.Claims = source?.Claims?.Select(x => context.Mapper.Map<ClientClaim>(x)).ToList() ?? new List<ClientClaim>();
            destination.IdentityProviderRestrictions = source?.IdentityProviderRestrictions?.Select(x => new ClientIdPRestriction { Provider = x }).ToList() ?? new List<ClientIdPRestriction>();
            destination.AllowedCorsOrigins = source?.AllowedCorsOrigins?.Select(x => new ClientCorsOrigin { Origin = x }).ToList() ?? new List<ClientCorsOrigin>();

            return destination;
        }
    }
}
