using System.Collections.Generic;
using System.Linq;
using AutoMapper;
using IdentityServer4.EntityFramework.Entities;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Dtos.Configuration;

namespace Skoruba.IdentityServer4.Admin.BusinessLogic.Mappers.Converters
{
    public class ClientPostLogoutRedirectUrisConverter : IValueConverter<List<ClientPostLogoutRedirectUri>, List<string>>
    {
        public List<string> Convert(List<ClientPostLogoutRedirectUri> sourceMember, ResolutionContext context)
        {
            return sourceMember?.Select(x => x.PostLogoutRedirectUri).ToList() ?? new List<string>();
        }
    }

    public class ClientRedirectUrisConverter : IValueConverter<List<ClientRedirectUri>, List<string>>
    {
        public List<string> Convert(List<ClientRedirectUri> sourceMember, ResolutionContext context)
        {
            return sourceMember?.Select(x => x.RedirectUri).ToList() ?? new List<string>();
        }
    }

    public class ClientScopesConverter : IValueConverter<List<ClientScope>, List<string>>
    {
        public List<string> Convert(List<ClientScope> sourceMember, ResolutionContext context)
        {
            return sourceMember?.Select(x => x.Scope).ToList() ?? new List<string>();
        }
    }

    public class ClientGrantTypesConverter : IValueConverter<List<ClientGrantType>, List<string>>
    {
        public List<string> Convert(List<ClientGrantType> sourceMember, ResolutionContext context)
        {
            return sourceMember?.Select(x => x.GrantType).ToList() ?? new List<string>();
        }
    }

    public class StringToClientPostLogoutRedirectUrisConverter : IValueConverter<List<string>, List<ClientPostLogoutRedirectUri>>
    {
        public List<ClientPostLogoutRedirectUri> Convert(List<string> sourceMember, ResolutionContext context)
        {
            return sourceMember?.Select(x => new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = x }).ToList() ?? new List<ClientPostLogoutRedirectUri>();
        }
    }

    public class StringToClientRedirectUrisConverter : IValueConverter<List<string>, List<ClientRedirectUri>>
    {
        public List<ClientRedirectUri> Convert(List<string> sourceMember, ResolutionContext context)
        {
            return sourceMember?.Select(x => new ClientRedirectUri { RedirectUri = x }).ToList() ?? new List<ClientRedirectUri>();
        }
    }

    public class StringToClientScopesConverter : IValueConverter<List<string>, List<ClientScope>>
    {
        public List<ClientScope> Convert(List<string> sourceMember, ResolutionContext context)
        {
            return sourceMember?.Select(x => new ClientScope { Scope = x }).ToList() ?? new List<ClientScope>();
        }
    }

    public class StringToClientGrantTypesConverter : IValueConverter<List<string>, List<ClientGrantType>>
    {
        public List<ClientGrantType> Convert(List<string> sourceMember, ResolutionContext context)
        {
            return sourceMember?.Select(x => new ClientGrantType { GrantType = x }).ToList() ?? new List<ClientGrantType>();
        }
    }
}
