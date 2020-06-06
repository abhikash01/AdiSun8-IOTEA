using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using STS.Model;
using STS.Model.Account;
using STS.Services;

namespace STS.Controllers
{
    public class UserController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILoginService<ApplicationUser> _loginService;
        private readonly SignInManager<ApplicationUser> _signInManager;
        public UserController(UserManager<ApplicationUser> userManager, ILoginService<ApplicationUser> loginService, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _loginService = loginService;
            _signInManager = signInManager;
        }

        [HttpGet]
        public async Task<ApplicationUser> GetUserProfile([FromQuery] string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);

            return user;
        }

        [HttpPost]
        [ProducesResponseType((int)HttpStatusCode.OK)]
        [ProducesResponseType((int)HttpStatusCode.BadRequest)]
        public async Task UpdateUserProfile([FromBody] ApplicationUser userContent)
        {
            var user = await _userManager.FindByNameAsync(userContent.UserName);
            if (user != null)
            {
                user.FirstName = userContent.FirstName;
                user.LastName = userContent.LastName;
                user.PhoneNumber = userContent.PhoneNumber;
                user.Email = userContent.Email;

                await _userManager.UpdateAsync(user);

                await _signInManager.RefreshSignInAsync(user);
            }

        }

        [HttpPost]
        [ProducesResponseType((int)HttpStatusCode.OK)]
        [ProducesResponseType((int)HttpStatusCode.BadRequest)]
        public async Task UpdatePassword([FromBody] ApplicationUser user, [FromBody] ChangePasswordViewModel passwordViewModel)
        {
            var istrue = await _userManager.CheckPasswordAsync(user, passwordViewModel.OldPassword);

            if (istrue)
            {
                await _userManager.ChangePasswordAsync(user, passwordViewModel.OldPassword,passwordViewModel.Newpassword);
            }
        }

    }
}