// Based on the IdentityServer4.EntityFramework - authors - Brock Allen & Dominick Baier.
// https://github.com/IdentityServer/IdentityServer4.EntityFramework

// Modified by Jan Škoruba

using System.Linq;
using System.Collections.Generic;
using AutoMapper;
using IdentityServer4.EntityFramework.Entities;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Dtos.Configuration;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Mappers.Converters;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Mappers.Resolvers;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Shared.Dtos.Common;
using Skoruba.IdentityServer4.Admin.EntityFramework.Extensions.Common;

namespace Skoruba.IdentityServer4.Admin.BusinessLogic.Mappers
{
    public class ClientMapperProfile : Profile
    {
        public ClientMapperProfile()
        {
            // entity to model
            CreateMap<Client, ClientDto>()
                .ForMember(dest => dest.ProtocolType, opt => opt.Condition(srs => srs != null))
                .ForMember(x => x.AllowedIdentityTokenSigningAlgorithms, opts => opts.ConvertUsing(AllowedSigningAlgorithmsConverter.Converter, x => x.AllowedIdentityTokenSigningAlgorithms))
                .BeforeMap((src, dest) => {
                    src.PostLogoutRedirectUris ??= new List<ClientPostLogoutRedirectUri>();
                    src.RedirectUris ??= new List<ClientRedirectUri>();
                    src.AllowedScopes ??= new List<ClientScope>();
                    src.AllowedGrantTypes ??= new List<ClientGrantType>();
                    src.IdentityProviderRestrictions ??= new List<ClientIdPRestriction>();
                    src.AllowedCorsOrigins ??= new List<ClientCorsOrigin>();
                })
                .ForMember(x => x.PostLogoutRedirectUris, opt => opt.MapFrom(src => src.PostLogoutRedirectUris.Select(x => x.PostLogoutRedirectUri).ToList()))
                .ForMember(x => x.RedirectUris, opt => opt.MapFrom(src => src.RedirectUris.Select(x => x.RedirectUri).ToList()))
                .ForMember(x => x.AllowedScopes, opt => opt.MapFrom(src => src.AllowedScopes.Select(x => x.Scope).ToList()))
                .ForMember(x => x.AllowedGrantTypes, opt => opt.MapFrom(src => src.AllowedGrantTypes.Select(x => x.GrantType).ToList()))
                .ForMember(x => x.IdentityProviderRestrictions, opt => opt.MapFrom(src => src.IdentityProviderRestrictions.Select(x => x.Provider).ToList()))
                .ForMember(x => x.AllowedCorsOrigins, opt => opt.MapFrom(src => src.AllowedCorsOrigins.Select(x => x.Origin).ToList()));

            CreateMap<ClientDto, Client>()
                .ForMember(x => x.AllowedIdentityTokenSigningAlgorithms, opts => opts.ConvertUsing(AllowedSigningAlgorithmsConverter.Converter, x => x.AllowedIdentityTokenSigningAlgorithms))
                .BeforeMap((src, dest) => {
                    src.PostLogoutRedirectUris ??= new List<string>();
                    src.RedirectUris ??= new List<string>();
                    src.AllowedScopes ??= new List<string>();
                    src.AllowedGrantTypes ??= new List<string>();
                    src.IdentityProviderRestrictions ??= new List<string>();
                    src.AllowedCorsOrigins ??= new List<string>();
                })
                .ForMember(x => x.PostLogoutRedirectUris, opt => opt.MapFrom(src => src.PostLogoutRedirectUris.Select(x => new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = x }).ToList()))
                .ForMember(x => x.RedirectUris, opt => opt.MapFrom(src => src.RedirectUris.Select(x => new ClientRedirectUri { RedirectUri = x }).ToList()))
                .ForMember(x => x.AllowedScopes, opt => opt.MapFrom(src => src.AllowedScopes.Select(x => new ClientScope { Scope = x }).ToList()))
                .ForMember(x => x.AllowedGrantTypes, opt => opt.MapFrom(src => src.AllowedGrantTypes.Select(x => new ClientGrantType { GrantType = x }).ToList()))
                .ForMember(x => x.IdentityProviderRestrictions, opt => opt.MapFrom(src => src.IdentityProviderRestrictions.Select(x => new ClientIdPRestriction { Provider = x }).ToList()))
                .ForMember(x => x.AllowedCorsOrigins, opt => opt.MapFrom(src => src.AllowedCorsOrigins.Select(x => new ClientCorsOrigin { Origin = x }).ToList()));

            CreateMap<ClientProperty, ClientPropertyDto>().ReverseMap();
            CreateMap<ClientClaim, ClientClaimDto>().ReverseMap();

            CreateMap<SelectItem, SelectItemDto>(MemberList.Destination)
                .ReverseMap();

            CreateMap<ClientGrantType, string>()
                .ConvertUsing(src => src.GrantType);
            CreateMap<string, ClientGrantType>()
                .ForMember(dest => dest.GrantType, opt => opt.MapFrom(src => src))
                .ForMember(dest => dest.Id, opt => opt.Ignore());

            CreateMap<ClientRedirectUri, string>()
                .ConvertUsing(src => src.RedirectUri);
            CreateMap<string, ClientRedirectUri>()
                .ForMember(dest => dest.RedirectUri, opt => opt.MapFrom(src => src))
                .ForMember(dest => dest.Id, opt => opt.Ignore());

            CreateMap<ClientPostLogoutRedirectUri, string>()
                .ConvertUsing(src => src.PostLogoutRedirectUri);
            CreateMap<string, ClientPostLogoutRedirectUri>()
                .ForMember(dest => dest.PostLogoutRedirectUri, opt => opt.MapFrom(src => src))
                .ForMember(dest => dest.Id, opt => opt.Ignore());

            CreateMap<ClientScope, string>()
                .ConvertUsing(src => src.Scope);
            CreateMap<string, ClientScope>()
                .ForMember(dest => dest.Scope, opt => opt.MapFrom(src => src))
                .ForMember(dest => dest.Id, opt => opt.Ignore());

            CreateMap<ClientSecret, ClientSecretDto>(MemberList.Destination)
                .ForMember(dest => dest.Type, opt => opt.Condition(srs => srs != null))
                .ReverseMap();

            CreateMap<ClientClaim, ClientClaimDto>(MemberList.None)
                .ConstructUsing(src => new ClientClaimDto() { Type = src.Type, Value = src.Value })
                .ReverseMap();

            CreateMap<ClientIdPRestriction, string>()
                .ConvertUsing(src => src.Provider);
            CreateMap<string, ClientIdPRestriction>()
                .ForMember(dest => dest.Provider, opt => opt.MapFrom(src => src))
                .ForMember(dest => dest.Id, opt => opt.Ignore());

            CreateMap<ClientCorsOrigin, string>()
                .ConvertUsing(src => src.Origin);
            CreateMap<string, ClientCorsOrigin>()
                .ForMember(dest => dest.Origin, opt => opt.MapFrom(src => src))
                .ForMember(dest => dest.Id, opt => opt.Ignore());

            CreateMap<ClientProperty, ClientPropertyDto>(MemberList.Destination)
                .ReverseMap();

            CreateMap<ClientSecret, ClientSecretsDto>(MemberList.Destination)
                .ForMember(dest => dest.Type, opt => opt.Condition(srs => srs != null))
                .ForMember(x => x.ClientSecretId, opt => opt.MapFrom(x => x.Id))
                .ForMember(x => x.ClientId, opt => opt.MapFrom(x => x.Client.Id));

            CreateMap<ClientClaim, ClientClaimsDto>(MemberList.Destination)
                .ForMember(dest => dest.Type, opt => opt.Condition(srs => srs != null))
                .ForMember(x => x.ClientClaimId, opt => opt.MapFrom(x => x.Id))
                .ForMember(x => x.ClientId, opt => opt.MapFrom(x => x.Client.Id));

            CreateMap<ClientProperty, ClientPropertiesDto>(MemberList.Destination)
                .ForMember(dest => dest.Key, opt => opt.Condition(srs => srs != null))
                .ForMember(x => x.ClientPropertyId, opt => opt.MapFrom(x => x.Id))
                .ForMember(x => x.ClientId, opt => opt.MapFrom(x => x.Client.Id));

            //PagedLists
            CreateMap<PagedList<ClientSecret>, ClientSecretsDto>(MemberList.Destination)
                .ForMember(x => x.ClientSecrets, opt => opt.MapFrom(src => src.Data));

            CreateMap<PagedList<ClientClaim>, ClientClaimsDto>(MemberList.Destination)
                .ForMember(x => x.ClientClaims, opt => opt.MapFrom(src => src.Data));

            CreateMap<PagedList<ClientProperty>, ClientPropertiesDto>(MemberList.Destination)
                .ForMember(x => x.ClientProperties, opt => opt.MapFrom(src => src.Data));

            CreateMap<PagedList<Client>, ClientsDto>(MemberList.Destination)
                .ForMember(x => x.Clients, opt => opt.MapFrom(src => src.Data));

            // model to entity
            CreateMap<ClientSecretsDto, ClientSecret>(MemberList.Source)
                        .ForMember(x => x.Client, dto => dto.MapFrom(src => new Client() { Id = src.ClientId }))
                        .ForMember(x => x.Id, opt => opt.MapFrom(src => src.ClientSecretId));

            CreateMap<ClientClaimsDto, ClientClaim>(MemberList.Source)
                .ForMember(x => x.Client, dto => dto.MapFrom(src => new Client() { Id = src.ClientId }))
                .ForMember(x => x.Id, opt => opt.MapFrom(src => src.ClientClaimId));

            CreateMap<ClientPropertiesDto, ClientProperty>(MemberList.Source)
                .ForMember(x => x.Client, dto => dto.MapFrom(src => new Client() { Id = src.ClientId }))
                .ForMember(x => x.Id, opt => opt.MapFrom(src => src.ClientPropertyId));
        }
    }
}
