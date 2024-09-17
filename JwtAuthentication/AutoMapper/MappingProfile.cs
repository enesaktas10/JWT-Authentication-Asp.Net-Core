using AutoMapper;
using JwtAuthentication.Dto;
using JwtAuthentication.Models.Entities;

namespace JwtAuthentication.AutoMapper
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<UserForRegistrationDto,User>();
        }
    }
}
