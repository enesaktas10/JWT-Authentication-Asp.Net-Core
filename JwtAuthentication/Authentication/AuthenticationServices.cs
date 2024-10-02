using JwtAuthentication.Dto;
using JwtAuthentication.Models.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
namespace JwtAuthentication.Authentication
{
    public class AuthenticationServices(UserManager<User> _userManager,IConfiguration _configuration)
    {
        private User? _user;

        #region
        //Kullanıcı adı ve şifreye bakarak böyle bir kullanıcı olup olmadığını sorguluyoruz.
        #endregion
        public async Task<bool> ValidateUser(UserForAuthenticationDto userForAuthDto)
        {
            _user = await _userManager.FindByNameAsync(userForAuthDto.UserName);

            var result = (_user != null && await _userManager.CheckPasswordAsync(_user, userForAuthDto.Password));

            return result;

        }


        //populateExp ifadesi true olursa refreshtokenla ilgili bir sure uzetmasi yapacagiz false olursa refresh tokenin suresune dokunmayacaagiz
        public async Task<TokenDto> CreateToken(bool populateExp)
        {
            
            var signinCredentials = GetSigninCredentials();

            //claims = hak,iddialari yada rolleri alacagiz oyle dusunebiliriz
            //Claim, kimlik doğrulama ve yetkilendirme işlemlerinde kullanıcının kimliği ve yetkileri hakkında bilgi taşıyan bir veri parçasıdır. Örneğin, bir kullanıcının adı veya rolü claim'ler ile ifade edilir ve bu bilgiler JWT token'larında saklanabilir.
            var claims = await GetClaims();

            var tokenOptions = GenerateTokenOptions(signinCredentials,claims);

            var refreshToken = GenerateRefreshToken();
            _user.RefreshToken = refreshToken;

            if (populateExp)
            {
                _user.RefreshTokenExpireTime = DateTime.Now.AddDays(7);
            }

            await _userManager.UpdateAsync(_user);

            var accessToken =  new JwtSecurityTokenHandler().WriteToken(tokenOptions);

            return new TokenDto()
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }

        public async Task<TokenDto> RefreshToken(TokenDto tokenDto)
        {
            //Süresi bitmiş tokenin kimlik bilgilerini elde ettim
            var principal = GetPrincipalFromExpiredToken(tokenDto.AccessToken);
            //Daha sonrasinda principal üzerinden süresi bitmil bu tokenin kime ait olduğunu hangi kullanıcıya ait olduğunu belirledim.
            var user = await _userManager.FindByNameAsync(principal.Identity.Name);


            if(user is null || user.RefreshToken != tokenDto.RefreshToken || user.RefreshTokenExpireTime <= DateTime.Now)
            {
                throw new Exception("Refresh Token Bad Request Exception . Invalid client request. The tokenDto has some invalid values.");
            }

            _user = user;
            return await CreateToken(populateExp: false);
        }

        #region
        //Bu metot, JWT (JSON Web Token) ile güvenli bir şekilde imza atmak için kullanılan SigningCredentials nesnesini oluşturmaktadır. JWT'ler, bir kullanıcının kimliğini doğrulamak ve yetkilendirmek için sıklıkla kullanılan bir token türüdür. Bu token'lar, genellikle sunucu tarafından imzalanarak doğrulukları sağlanır ve bu imzanın güvenliğini sağlamak için SigningCredentials kullanılır.
        //Bu metodun amacı, JWT token'larının imzalanması için gereken SigningCredentials nesnesini sağlamaktır. JWT token'larının doğruluğunu ve güvenliğini sağlamak için bu imzalama bilgisi kullanılır. Bu sayede, token'ın yetkisiz kişiler tarafından değiştirilmediği veya sahte olmadığı garantilenir. Metot, konfigürasyon ayarlarından gizli anahtarı alır, bu anahtarı bir SymmetricSecurityKey nesnesine dönüştürür ve bu anahtarı kullanarak bir SigningCredentials nesnesi oluşturur. Bu nesne, JWT'nin imzalanmasında kullanılır.
        #endregion
        private SigningCredentials GetSigninCredentials()
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var key = Encoding.UTF8.GetBytes(jwtSettings["secretKey"]);
            var secret = new SymmetricSecurityKey(key);

            return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);

        }

        #region
        //Bu metodun temel amacı, bir kullanıcının kimlik bilgilerini ve rollerini içeren claim'leri toplamak ve bir liste olarak döndürmektir. Claim'ler, genellikle kimlik doğrulama ve yetkilendirme süreçlerinde kullanılır. JWT gibi token tabanlı sistemlerde, bu claim'ler token'ın içerisine eklenir ve token'ın doğruluğunu sağlamak için kullanılır
        #endregion
        private async Task<List<Claim>> GetClaims()
        {
            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name,_user.UserName)                                
            };

            var roles = await _userManager
                .GetRolesAsync(_user);

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            return claims;
        }

        #region
        //Bu metodun amacı, JWT (JSON Web Token) oluşturmak için gerekli tüm ayarları yapılandırarak bir JwtSecurityToken nesnesi oluşturmaktır. Token'ın geçerlilik süresi, imzalama bilgileri ve claim'ler gibi bilgileri içerir ve bu token, kullanıcının kimlik doğrulama işlemlerinde güvenli bir şekilde kullanılır.
        #endregion
        private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials , List<Claim> claims)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");

            var tokenOptions = new JwtSecurityToken(
                issuer: jwtSettings["validIssuer"],
                audience: jwtSettings["validAudience"],
                //Token içinde yer alacak claim'ler listesi. Claim'ler, kullanıcının kimlik bilgilerini ve rollerini içerir ve JWT'ye dahil edilir.
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(jwtSettings["expires"])),
                signingCredentials: signingCredentials);

            return tokenOptions;
        }

        //buradaki mantik su tahmin edilmesi zor bir ifade uretecegiz ve bu ifade ile belirli bir endpointe gelindigi zaman tokeni yenileyip kullanicinin tokenini yenilmes olacagiz bu sekilde yeni tokenla devam etmesini saglayacagiz
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        #region
        //Principal gordugumuz yerde Burada kullanici bilgilerini ihtiyac vardir 
        //Süresi geçmiş tokendan gerekli bilgileri alacağız
        #endregion
        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["secretKey"];

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings["validIssuer"],
                ValidAudience = jwtSettings["validAudience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;

            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);

            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken is null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token.");
            }

            return principal;
        }

    }
}
