namespace JwtAuthentication.Dto
{
    public record TokenDto
    {
        //init = bu nesne tanimlandigi anda degerleri verilecek daha sonrasinda immutable(degistirelemez) olarak kullanilacak.
        public String AccessToken { get; init; }
        public String RefreshToken { get; init; }
    }
}
