using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace SimpleAuthExtensions.Authentication
{
    public interface ISimpleAuthenticationService
    {
        Task<AuthenticateResult> Authenticate(string authorizationHeaderName, string bearerSchemeName, string schemeName, HttpRequest request);
    }
}
