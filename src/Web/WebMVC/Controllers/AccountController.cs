using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;


namespace WebMVC.Controllers
{
    [Authorize(AuthenticationSchemes = "oidc")]
    public class AccountController : Controller
    {
        
        public IActionResult Index()
        {
            return View();
        }

        
        public async Task<IActionResult> SignIn(string returnUrl)
        {
            var user = User as ClaimsPrincipal;
            var token = await HttpContext.GetTokenAsync("access_token");

            if (token != null)
            {
                ViewData["access_token"] = token;
            }

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
        public async Task<IActionResult> Signout()
        {
            await HttpContext.SignOutAsync("Cookies");
            await HttpContext.SignOutAsync("oidc");

            var homeUrl = Url.Action(nameof(HomeController.Index), "Home");
            return new SignOutResult("oidc",
                new AuthenticationProperties { RedirectUri = homeUrl });
        }

        public async Task<IActionResult> Register()
        {
            return Redirect("http://localhost:5000/Account/Register");
        }
    }
}