using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace SimpleAuthExtensions.Authorization
{
    public interface ISimpleAuthorizationService
    {
        Task<AuthenticateResult> Authorize(string authorizationHeaderName, string bearerSchemeName, string schemeName, HttpRequest request);
    }
}
