using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SimpleAuthExtensions.Authentication;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace SimpleAuthExtensions.Authentication
{
    public class SimpleAuthenticationHandler : AuthenticationHandler<SimpleAuthenticationOptions>
    {
        private const string AuthorizationHeaderName = "Authorization";
        private const string BearerSchemeName = "Bearer";
        private readonly ISimpleAuthenticationService authenticationService;

        public SimpleAuthenticationHandler(
            IOptionsMonitor<SimpleAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ISimpleAuthenticationService authenticationService)
            : base(options, logger, encoder, clock)
        {
            this.authenticationService = authenticationService;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            return await authenticationService.Authenticate(AuthorizationHeaderName, BearerSchemeName, Scheme.Name, Request);
        }
    }
}
