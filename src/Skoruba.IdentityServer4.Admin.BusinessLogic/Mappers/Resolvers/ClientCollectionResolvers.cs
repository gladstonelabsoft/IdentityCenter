using System.Collections.Generic;
using System.Linq;
using AutoMapper;
using IdentityServer4.EntityFramework.Entities;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Dtos.Configuration;

namespace Skoruba.IdentityServer4.Admin.BusinessLogic.Mappers.Resolvers
{
    public class ClientToPostLogoutRedirectUrisResolver : IValueResolver<Client, ClientDto, List<string>>
    {
        public List<string> Resolve(Client source, ClientDto destination, List<string> destMember, ResolutionContext context)
        {
            return source.PostLogoutRedirectUris?.Select(x => x.PostLogoutRedirectUri).ToList() ?? new List<string>();
        }
    }

    public class ClientToRedirectUrisResolver : IValueResolver<Client, ClientDto, List<string>>
    {
        public List<string> Resolve(Client source, ClientDto destination, List<string> destMember, ResolutionContext context)
        {
            return source.RedirectUris?.Select(x => x.RedirectUri).ToList() ?? new List<string>();
        }
    }

    public class ClientToScopesResolver : IValueResolver<Client, ClientDto, List<string>>
    {
        public List<string> Resolve(Client source, ClientDto destination, List<string> destMember, ResolutionContext context)
        {
            return source.AllowedScopes?.Select(x => x.Scope).ToList() ?? new List<string>();
        }
    }

    public class ClientToGrantTypesResolver : IValueResolver<Client, ClientDto, List<string>>
    {
        public List<string> Resolve(Client source, ClientDto destination, List<string> destMember, ResolutionContext context)
        {
            return source.AllowedGrantTypes?.Select(x => x.GrantType).ToList() ?? new List<string>();
        }
    }

    public class DtoToPostLogoutRedirectUrisResolver : IValueResolver<ClientDto, Client, List<ClientPostLogoutRedirectUri>>
    {
        public List<ClientPostLogoutRedirectUri> Resolve(ClientDto source, Client destination, List<ClientPostLogoutRedirectUri> destMember, ResolutionContext context)
        {
            return source.PostLogoutRedirectUris?.Select(uri => new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = uri }).ToList() ?? new List<ClientPostLogoutRedirectUri>();
        }
    }

    public class DtoToRedirectUrisResolver : IValueResolver<ClientDto, Client, List<ClientRedirectUri>>
    {
        public List<ClientRedirectUri> Resolve(ClientDto source, Client destination, List<ClientRedirectUri> destMember, ResolutionContext context)
        {
            return source.RedirectUris?.Select(uri => new ClientRedirectUri { RedirectUri = uri }).ToList() ?? new List<ClientRedirectUri>();
        }
    }

    public class DtoToScopesResolver : IValueResolver<ClientDto, Client, List<ClientScope>>
    {
        public List<ClientScope> Resolve(ClientDto source, Client destination, List<ClientScope> destMember, ResolutionContext context)
        {
            return source.AllowedScopes?.Select(scope => new ClientScope { Scope = scope }).ToList() ?? new List<ClientScope>();
        }
    }

    public class DtoToGrantTypesResolver : IValueResolver<ClientDto, Client, List<ClientGrantType>>
    {
        public List<ClientGrantType> Resolve(ClientDto source, Client destination, List<ClientGrantType> destMember, ResolutionContext context)
        {
            return source.AllowedGrantTypes?.Select(grant => new ClientGrantType { GrantType = grant }).ToList() ?? new List<ClientGrantType>();
        }
    }
}
