using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace SimpleAuthExtensions.Authentication
{
    public class SimpleAuthenticationOptions : AuthenticationSchemeOptions
    {
        public string Secret { get; set; }
        public TokenValidationParameters TokenValidationParameters { get; set; }
    }
}
