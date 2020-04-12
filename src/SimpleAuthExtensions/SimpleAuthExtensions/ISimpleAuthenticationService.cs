using System.Threading.Tasks;

namespace SimpleAuthExtensions
{
    public interface ISimpleAuthenticationService
    {
        Task<bool> IsValidUserAsync(string user, string password);
    }
}
