using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace SimpleAuthExtensions
{
    public class SimpleAuthenticationHandler : AuthenticationHandler<SimpleAuthenticationOptions>
    {
        private const string AuthorizationHeaderName = "Authorization";
        private const string BearerSchemeName = "Bearer";
        private readonly ISimpleAuthenticationService _authenticationService;

        public SimpleAuthenticationHandler(
            IOptionsMonitor<SimpleAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ISimpleAuthenticationService authenticationService)
            : base(options, logger, encoder, clock)
        {
            _authenticationService = authenticationService;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey(AuthorizationHeaderName))
            {
                //Authorization header not in request
                return AuthenticateResult.NoResult();
            }

            if (!AuthenticationHeaderValue.TryParse(Request.Headers[AuthorizationHeaderName], out AuthenticationHeaderValue headerValue))
            {
                //Invalid Authorization header
                return AuthenticateResult.NoResult();
            }

            if (!BearerSchemeName.Equals(headerValue.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                //Not Basic authentication header
                return AuthenticateResult.NoResult();
            }

            if (string.IsNullOrEmpty(headerValue.Parameter))
            {
                return AuthenticateResult.Fail("Unauthorized");
            }

            try
            {
                return ValidateToken(headerValue.Parameter);
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail(ex.Message);
            }
        }

        private AuthenticateResult ValidateToken(string token)
        {
            var tokenResponse = GetToken(token);
            if (!tokenResponse.claimsPrincipal.Identity.IsAuthenticated)
            {
                return AuthenticateResult.Fail("Unauthorized");
            }

            var identity = new ClaimsIdentity(tokenResponse.claimsPrincipal.Claims, Scheme.Name);
            var principal = new System.Security.Principal.GenericPrincipal(identity, null);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }

        private (ClaimsPrincipal claimsPrincipal, SecurityToken securityToken) GetToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var parameters = Options.TokenValidationParameters;
            var claimsPrincipal = tokenHandler.ValidateToken(token, parameters, out var validatedToken);
            return (claimsPrincipal, validatedToken);
        }
    }
}
