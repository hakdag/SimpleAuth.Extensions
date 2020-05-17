using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using SimpleAuthExtensions.Authentication;
using SimpleAuthExtensions.Authorization;
using SimpleAuthExtensions.Business;
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
            builder.Services.AddHttpClient<IAuthorizationClient, AuthorizationClient>("AuthClient", conf => conf.BaseAddress = new Uri(simpleAuthenticationOptions.AuthApiBaseAddress));
            builder.Services.AddHttpClient<ILockAccountClient, LockAccountClient>("AuthClient", conf => conf.BaseAddress = new Uri(simpleAuthenticationOptions.AuthApiBaseAddress));
            builder.Services.AddHttpClient<IUnLockAccountClient, UnLockAccountClient>("AuthClient", conf => conf.BaseAddress = new Uri(simpleAuthenticationOptions.AuthApiBaseAddress));
            builder.Services.AddHttpClient<IChangePasswordClient, ChangePasswordClient>("AuthClient", conf => conf.BaseAddress = new Uri(simpleAuthenticationOptions.AuthApiBaseAddress));
            builder.Services.AddHttpClient<IRolesClient, RolesClient>("AuthClient", conf => conf.BaseAddress = new Uri(simpleAuthenticationOptions.AuthApiBaseAddress));
            builder.Services.AddHttpClient<IUserRoleClient, UserRoleClient>("AuthClient", conf => conf.BaseAddress = new Uri(simpleAuthenticationOptions.AuthApiBaseAddress));
            builder.Services.AddHttpClient<IUsersClient, UsersClient>("AuthClient", conf => conf.BaseAddress = new Uri(simpleAuthenticationOptions.AuthApiBaseAddress));
            builder.Services.AddHttpClient<IPasswordResetClient, PasswordResetClient>("AuthClient", conf => conf.BaseAddress = new Uri(simpleAuthenticationOptions.AuthApiBaseAddress));
            builder.Services.AddHttpClient<IGeneratePasswordResetKeyClient, GeneratePasswordResetKeyClient>("AuthClient", conf => conf.BaseAddress = new Uri(simpleAuthenticationOptions.AuthApiBaseAddress));
            builder.Services.AddHttpClient<IValidatePasswordResetKeyClient, ValidatePasswordResetKeyClient>("AuthClient", conf => conf.BaseAddress = new Uri(simpleAuthenticationOptions.AuthApiBaseAddress));
            builder.Services.AddScoped<ISimpleAuthBusiness, SimpleAuthBusiness>();

            return builder.AddScheme<AuthenticationSchemeOptions, SimpleAuthenticationHandler>(SimpleAuthenticationDefaults.AuthenticationScheme, _ => { });
        }
    }
}
