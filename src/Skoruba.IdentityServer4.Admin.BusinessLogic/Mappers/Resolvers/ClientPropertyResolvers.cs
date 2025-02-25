using System.Collections.Generic;
using AutoMapper;
using IdentityServer4.EntityFramework.Entities;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Dtos.Configuration;

namespace Skoruba.IdentityServer4.Admin.BusinessLogic.Mappers.Resolvers
{
    public class ClientPropertiesResolver : IValueResolver<Client, ClientDto, List<ClientPropertyDto>>
    {
        public List<ClientPropertyDto> Resolve(Client source, ClientDto destination, List<ClientPropertyDto> destMember, ResolutionContext context)
        {
            return source.Properties == null ? new List<ClientPropertyDto>() : context.Mapper.Map<List<ClientPropertyDto>>(source.Properties);
        }
    }

    public class ClientClaimsResolver : IValueResolver<Client, ClientDto, List<ClientClaimDto>>
    {
        public List<ClientClaimDto> Resolve(Client source, ClientDto destination, List<ClientClaimDto> destMember, ResolutionContext context)
        {
            return source.Claims == null ? new List<ClientClaimDto>() : context.Mapper.Map<List<ClientClaimDto>>(source.Claims);
        }
    }

    public class DtoPropertiesResolver : IValueResolver<ClientDto, Client, List<ClientProperty>>
    {
        public List<ClientProperty> Resolve(ClientDto source, Client destination, List<ClientProperty> destMember, ResolutionContext context)
        {
            return source.Properties == null ? new List<ClientProperty>() : context.Mapper.Map<List<ClientProperty>>(source.Properties);
        }
    }

    public class DtoClaimsResolver : IValueResolver<ClientDto, Client, List<ClientClaim>>
    {
        public List<ClientClaim> Resolve(ClientDto source, Client destination, List<ClientClaim> destMember, ResolutionContext context)
        {
            return source.Claims == null ? new List<ClientClaim>() : context.Mapper.Map<List<ClientClaim>>(source.Claims);
        }
    }
}
