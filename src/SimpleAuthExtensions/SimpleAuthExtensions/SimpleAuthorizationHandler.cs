using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace SimpleAuthExtensions
{
    public class OnlyManagersRequirement : IAuthorizationRequirement
    {
    }

    public class SimpleAuthorizationHandler : AuthorizationHandler<OnlyManagersRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, OnlyManagersRequirement requirement)
        {
            if (context.User.IsInRole("Manager"))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
