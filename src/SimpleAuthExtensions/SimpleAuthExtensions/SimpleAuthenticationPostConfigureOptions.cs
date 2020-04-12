using Microsoft.Extensions.Options;
using System;

namespace SimpleAuthExtensions
{
    public class SimpleAuthenticationPostConfigureOptions : IPostConfigureOptions<SimpleAuthenticationOptions>
    {
        public void PostConfigure(string name, SimpleAuthenticationOptions options)
        {
            if (options.TokenValidationParameters == null)
            {
                throw new InvalidOperationException("TokenValidationParameters must be provided in the options.");
            }
        }
    }
}
