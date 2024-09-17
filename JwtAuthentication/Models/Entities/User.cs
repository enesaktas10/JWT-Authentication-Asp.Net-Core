using Microsoft.AspNetCore.Identity;

namespace JwtAuthentication.Models.Entities
{
    public class User : IdentityUser
    {
        public String? FirstName { get; set; }
        public String? LastName { get; set; }
        public String? RefreshToken { get; set; }
        public DateTime RefreshTokenExpireTime { get; set; }
    }
}
