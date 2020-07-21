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
        private bool AuthenticateSucceeded = false;
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
            var result = await authorizationService.Authorize(AuthorizationHeaderName, BearerSchemeName, Scheme.Name, Request);
            AuthenticateSucceeded = result.Succeeded;
            return result;
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (!AuthenticateSucceeded)
            {
                Response.StatusCode = 401;
            }
            return Task.CompletedTask;
        }
    }
}
