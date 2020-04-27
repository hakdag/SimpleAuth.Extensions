using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace SimpleAuthExtensions
{
    public interface ISimpleAuthenticationService
    {
        Task<AuthenticateResult> Authenticate(string authorizationHeaderName, string bearerSchemeName, string schemeName, HttpRequest request);
    }
}
