using Microsoft.AspNetCore.Authorization;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SimpleAuthExtensions
{
    public class SimpleRequirement : IAuthorizationRequirement
    {
        public string[] Roles { get; set; }
    }

    public class SimpleAuthorizationHandler : AuthorizationHandler<SimpleRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, SimpleRequirement requirement)
        {
            if (context.User.HasClaim(c => c.Type.EndsWith("/identity/claims/role") && requirement.Roles.Contains(c.Value)))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
