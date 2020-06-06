using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using STS.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JSR.API
{
    [Route("identity")]
    [Authorize]
    public class IdentityController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        public IdentityController()
        {
            
        }
        
        [HttpGet]
        public async Task<ActionResult<string>> Get()
        {
          //  var user = await _userManager.FindByNameAsync(userName);

            return User.FindFirst(x=>x.Type == "First Name").Value.ToString();
        }

    }
}
