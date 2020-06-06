using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebMVC.Models;
using WebMVC.Services;
using WebMVC.Services.ManageUserProfileService;

namespace WebMVC.Controllers
{
    [Authorize(AuthenticationSchemes = "oidc")]
    public class UserController : Controller
    {
        private IManageUserProfile _manageUserProfile;
        private readonly IIdentityParser<ApplicationUser> _appUserParser;
        public UserController(IManageUserProfile manageUserProfile, IIdentityParser<ApplicationUser> appUserParser)
        {
            _manageUserProfile = manageUserProfile;
            _appUserParser = appUserParser;
        }

        [Authorize(AuthenticationSchemes = "oidc")]
        [HttpGet]
        public async Task<IActionResult> ManageProfile()
        {
            var user = _appUserParser.Parse(HttpContext.User);

            user = await _manageUserProfile.GetUserProfile(user.UserName);
            var appuser = _manageUserProfile.GetAppUser(user);
            return View(appuser);
        }

        [Authorize(AuthenticationSchemes = "oidc")]
        [HttpPost]
        public async Task<IActionResult> ManageProfile(ApplicationUser appuser)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var user = _appUserParser.Parse(HttpContext.User);
                   

                    await _manageUserProfile.UpdateUserProfile(appuser);
                    user = await _manageUserProfile.GetUserProfile(user.UserName);
                    ModelState.AddModelError("Success", $"Profile Updated Successfully");
                    return View(user);
                }
            }
            catch(Exception ex)
            {
                ModelState.AddModelError("Error", $"It was not possible to Update profile, please try later on ({ex.GetType().Name} - {ex.Message})");

            }
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> ChangePassword()
        {
            var vm = builChangePasswordVM();

            return View(vm);
        }
        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel changePasswordViewModel)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var user = _appUserParser.Parse(HttpContext.User);
                    await _manageUserProfile.UpdatePassword(user,changePasswordViewModel);
                }
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("Error", $"It was not possible to Update Password, please try later on ({ex.GetType().Name} - {ex.Message})");
            }
            return View();
        }

        private ChangePasswordViewModel builChangePasswordVM()
        {
            var vm = new ChangePasswordViewModel();

            return vm;
        }
    }
}