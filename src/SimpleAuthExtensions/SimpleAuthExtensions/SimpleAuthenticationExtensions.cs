using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using SimpleAuthExtensions.Authentication;
using SimpleAuthExtensions.Authorization;
using SimpleAuthExtensions.Service;
using System;

namespace SimpleAuthExtensions
{
    public static class SimpleAuthenticationExtensions
    {
        private readonly static string authApiBaseAddress = "http://localhost:4000/";

        public static AuthenticationBuilder AddSimpleAuth<TAuthService>(this AuthenticationBuilder builder)
            where TAuthService : class, ISimpleAuthorizationService
        {
            return AddSimpleAuth<TAuthService>(builder, new SimpleAuthenticationOptions { AuthApiBaseAddress = authApiBaseAddress });
        }
        public static AuthenticationBuilder AddSimpleAuth<TAuthService>(this AuthenticationBuilder builder, SimpleAuthenticationOptions simpleAuthenticationOptions)
            where TAuthService : class, ISimpleAuthorizationService
        {
            builder.Services.AddTransient<ISimpleAuthorizationService, TAuthService>();
            builder.Services.AddHttpClient<IAuthorizationClient, AuthorizationClient>("AuthorizationClient", conf => conf.BaseAddress = new Uri(simpleAuthenticationOptions.AuthApiBaseAddress));

            return builder.AddScheme<AuthenticationSchemeOptions, SimpleAuthenticationHandler>(SimpleAuthenticationDefaults.AuthenticationScheme, _ => { });
        }
    }
}
