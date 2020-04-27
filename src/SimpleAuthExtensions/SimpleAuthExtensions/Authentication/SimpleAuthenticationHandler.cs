using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SimpleAuthExtensions.Authorization;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace SimpleAuthExtensions.Authentication
{
    public class SimpleAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private const string AuthorizationHeaderName = "Authorization";
        private const string BearerSchemeName = "Bearer";
        private readonly ISimpleAuthorizationService authorizationService;

        public SimpleAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ISimpleAuthorizationService authorizationService)
            : base(options, logger, encoder, clock)
        {
            this.authorizationService = authorizationService;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            return await authorizationService.Authorize(AuthorizationHeaderName, BearerSchemeName, Scheme.Name, Request);
        }
    }
}
