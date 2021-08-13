using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Tweetbook.Contracts.Requests;
using Tweetbook.Domain;

namespace Tweetbook.Services
{
    public interface IIdentityService
    {
        Task<AuthResult> RegisterAsync(string email, string password);
        Task<AuthResult> LoginAsync(string email, string password);
        
    }
}
