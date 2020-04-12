using System.Threading.Tasks;

namespace SimpleAuthExtensions
{
    public class SimpleAuthenticationService : ISimpleAuthenticationService
    {
        public async Task<bool> IsValidUserAsync(string user, string password)
        {
            return await Task.FromResult(user.Equals("admin") && password.Equals("qwe123"));
        }
    }
}
