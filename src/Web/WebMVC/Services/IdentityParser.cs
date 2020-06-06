using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using WebMVC.Models;

namespace WebMVC.Services
{
    public class IdentityParser : IIdentityParser<ApplicationUser>
    {
        public ApplicationUser Parse(IPrincipal principal)
        {
            if (principal is ClaimsPrincipal claims)
            {
                return new ApplicationUser
                {

                    Email = claims.Claims.FirstOrDefault(x => x.Type == "Email")?.Value ?? "",
                    Id = claims.Claims.FirstOrDefault(x => x.Type == "sub")?.Value ?? "",
                    LastName = claims.Claims.FirstOrDefault(x => x.Type == "Last Name")?.Value ?? "",
                    FirstName = claims.Claims.FirstOrDefault(x => x.Type == "First Name")?.Value ?? "",
                    PhoneNumber = claims.Claims.FirstOrDefault(x => x.Type == "phone_number")?.Value ?? "",
                    UserName = claims.Claims.FirstOrDefault(x=>x.Type == "preferred_username")?.Value??""
                };
            }
            throw new ArgumentException(message: "The principal must be a ClaimsPrincipal", paramName: nameof(principal));

        }

    }
}
