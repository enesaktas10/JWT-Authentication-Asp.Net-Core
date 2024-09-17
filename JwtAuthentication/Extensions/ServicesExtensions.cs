using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace JwtAuthentication.Extensions
{
    public static class ServicesExtensions
    {
        public static void ConfigureJWT(this IServiceCollection services,IConfiguration configuration)
        {
            var jwtSettings = configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["secretKey"];

            services.AddAuthentication(opt =>
            {
                opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;//JWT tabanlı kimlik doğrulamanın varsayılan şemasıdır
                opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;//Bir kullanıcı kimliği doğrulanmadığında veya yetkisiz bir kaynağa erişmeye çalıştığında uygulama, JWT ile kimlik doğrulama yapmasını isteyecektir. Örneğin, kullanıcının token'ı eksikse veya geçersizse bu şema devreye girerek doğru kimlik bilgilerini talep eder.

            }).AddJwtBearer(options =>
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    //Issuer'ın doğrulanıp doğrulanmayacağını belirtir. Issuer, token'ı oluşturan tarafı temsil eder.
                    //Eğer true ise, token’ın kim tarafından oluşturulduğunun kontrol edilmesi gerekir (yani ValidIssuer ile eşleşmeli).
                    ValidateIssuer = true,
                    //Bu parametre, token'ı kullanan hedef kitlenin (audience) doğrulanıp doğrulanmayacağını belirtir. Genellikle, token belirli bir kullanıcı grubu ya da uygulama tarafından kullanılır.
                    //Eğer true ise, token’ın hedef kitlesi (audience) kontrol edilir ve ValidAudience ile eşleşmeli.
                    ValidateAudience = true,
                    //Bu, token’ın geçerlilik süresinin (başlangıç ve bitiş zamanı) kontrol edilip edilmeyeceğini belirtir. Token'ın süresi dolmuşsa geçersiz sayılır.
                    ValidateLifetime = true,
                    //Token'ın imza anahtarının doğrulanıp doğrulanmayacağını belirtir. Bu, token’ın güvenilir bir kaynak tarafından imzalanıp imzalanmadığını doğrular.
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings["validIssuer"],
                    ValidAudience = jwtSettings["validAudience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
                }
            ); ;
        }

    }
}
