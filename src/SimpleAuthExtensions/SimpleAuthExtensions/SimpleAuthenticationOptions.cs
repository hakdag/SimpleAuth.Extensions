using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace SimpleAuthExtensions
{
    public class SimpleAuthenticationOptions : AuthenticationSchemeOptions
    {
        public TokenValidationParameters TokenValidationParameters { get; set; }
    }
}
