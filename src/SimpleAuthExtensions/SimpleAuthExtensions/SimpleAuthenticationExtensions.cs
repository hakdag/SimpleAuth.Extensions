using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;

namespace SimpleAuthExtensions
{
    public static class SimpleAuthenticationExtensions
    {
        public static AuthenticationBuilder AddSimpleAuth<TAuthService>(this AuthenticationBuilder builder)
            where TAuthService : class, ISimpleAuthenticationService
        {
            return AddSimpleAuth<TAuthService>(builder, SimpleAuthenticationDefaults.AuthenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddSimpleAuth<TAuthService>(this AuthenticationBuilder builder, string authenticationScheme)
            where TAuthService : class, ISimpleAuthenticationService
        {
            return AddSimpleAuth<TAuthService>(builder, authenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddSimpleAuth<TAuthService>(this AuthenticationBuilder builder, Action<SimpleAuthenticationOptions> configureOptions)
            where TAuthService : class, ISimpleAuthenticationService
        {
            return AddSimpleAuth<TAuthService>(builder, SimpleAuthenticationDefaults.AuthenticationScheme, configureOptions);
        }

        public static AuthenticationBuilder AddSimpleAuth<TAuthService>(this AuthenticationBuilder builder, string authenticationScheme, Action<SimpleAuthenticationOptions> configureOptions)
            where TAuthService : class, ISimpleAuthenticationService
        {
            builder.Services.AddSingleton<IPostConfigureOptions<SimpleAuthenticationOptions>, SimpleAuthenticationPostConfigureOptions>();
            builder.Services.AddTransient<ISimpleAuthenticationService, TAuthService>();

            return builder.AddScheme<SimpleAuthenticationOptions, SimpleAuthenticationHandler>(
                authenticationScheme, configureOptions);
        }
    }
}
