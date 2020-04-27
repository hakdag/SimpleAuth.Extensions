using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using SimpleAuthExtensions.Service;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SimpleAuthExtensions
{
    public class SimpleAuthenticationService : ISimpleAuthenticationService
    {
        private readonly IAuthorizationClient authorizationClient;

        public SimpleAuthenticationService(IAuthorizationClient authorizationClient)
        {
            this.authorizationClient = authorizationClient;
        }

        public async Task<AuthenticateResult> Authenticate(string authorizationHeaderName, string bearerSchemeName, string schemeName, HttpRequest request)
        {
            if (!request.Headers.ContainsKey(authorizationHeaderName))
            {
                // Authorization header is not in the request
                return AuthenticateResult.NoResult();
            }

            if (!AuthenticationHeaderValue.TryParse(request.Headers[authorizationHeaderName], out AuthenticationHeaderValue headerValue))
            {
                // Invalid Authorization header
                return AuthenticateResult.NoResult();
            }

            if (!bearerSchemeName.Equals(headerValue.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                // Not Bearer authentication header
                return AuthenticateResult.NoResult();
            }

            if (string.IsNullOrEmpty(headerValue.Parameter))
            {
                return AuthenticateResult.Fail("Unauthorized");
            }

            try
            {
                var result = await authorizationClient.PostAsync(new AuthorizationModel { Token = headerValue.Parameter });
                if (result.IsAuthorized)
                {
                    var ticket = GetTicket(schemeName, result);
                    return AuthenticateResult.Success(ticket);
                }

                return AuthenticateResult.Fail("Unauthorized");
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail(ex.Message);
            }
        }

        private AuthenticationTicket GetTicket(string schemeName, AuthorizationResult result)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, result.UserName)
            };
            claims.AddRange(result.Roles.Select(role => new Claim(ClaimTypes.Role, role)));
            var identity = new ClaimsIdentity(claims, schemeName);
            var principal = new System.Security.Principal.GenericPrincipal(identity, null);
            var ticket = new AuthenticationTicket(principal, schemeName);
            return ticket;
        }
    }
}
