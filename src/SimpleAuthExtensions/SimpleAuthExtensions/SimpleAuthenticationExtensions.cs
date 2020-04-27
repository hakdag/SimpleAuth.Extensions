using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SimpleAuthExtensions.Authentication;
using SimpleAuthExtensions.Authorization;
using SimpleAuthExtensions.Service;
using System;

namespace SimpleAuthExtensions
{
    public static class SimpleAuthenticationExtensions
    {
        public static AuthenticationBuilder AddSimpleAuth<TAuthService>(this AuthenticationBuilder builder)
            where TAuthService : class, ISimpleAuthorizationService
        {
            return AddSimpleAuth<TAuthService>(builder, SimpleAuthenticationDefaults.AuthenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddSimpleAuth<TAuthService>(this AuthenticationBuilder builder, string authenticationScheme)
            where TAuthService : class, ISimpleAuthorizationService
        {
            return AddSimpleAuth<TAuthService>(builder, authenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddSimpleAuth<TAuthService>(this AuthenticationBuilder builder, Action<SimpleAuthenticationOptions> configureOptions)
            where TAuthService : class, ISimpleAuthorizationService
        {
            return AddSimpleAuth<TAuthService>(builder, SimpleAuthenticationDefaults.AuthenticationScheme, configureOptions);
        }

        public static AuthenticationBuilder AddSimpleAuth<TAuthService>(this AuthenticationBuilder builder, string authenticationScheme, Action<SimpleAuthenticationOptions> configureOptions)
            where TAuthService : class, ISimpleAuthorizationService
        {
            builder.Services.AddSingleton<IPostConfigureOptions<SimpleAuthenticationOptions>, SimpleAuthenticationPostConfigureOptions>();
            builder.Services.AddTransient<ISimpleAuthorizationService, TAuthService>();
            builder.Services.AddHttpClient<IAuthorizationClient, AuthorizationClient>("AuthorizationClient");

            return builder.AddScheme<SimpleAuthenticationOptions, SimpleAuthenticationHandler>(
                authenticationScheme, configureOptions);
        }
    }
}
