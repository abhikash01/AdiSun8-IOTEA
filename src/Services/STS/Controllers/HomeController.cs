using IdentityServer4.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using STS.Model;
using STS.Services;
using System.Threading.Tasks;

namespace STS
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class HomeController : Controller
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IWebHostEnvironment _environment;
        private readonly ILogger _logger;
        private readonly IRedirectService _redirectSvc;
        private readonly UserManager<ApplicationUser> _userManager;
        public HomeController(IIdentityServerInteractionService interaction, IWebHostEnvironment environment
            , ILogger<HomeController> logger
            , IRedirectService redirectSvc
            ,UserManager<ApplicationUser> userManager)
        {
            _interaction = interaction;
            _environment = environment;
            _logger = logger;
            _redirectSvc = redirectSvc;
            _userManager = userManager;
        }

        public IActionResult Index()
        {
            if (_environment.IsDevelopment())
            {
                // only show in development
                return View();
            }

            _logger.LogInformation("Homepage is disabled in production. Returning 404.");
            return NotFound();
        }

        /// <summary>
        /// Shows the error page
        /// </summary>
        public async Task<IActionResult> Error(string errorId)
        {
            var vm = new ErrorViewModel();

            // retrieve error details from identityserver
            var message = await _interaction.GetErrorContextAsync(errorId);
            if (message != null)
            {
                vm.Error = message;

                if (!_environment.IsDevelopment())
                {
                    // only show in development
                    message.ErrorDescription = null;
                }
            }

            return View("Error", vm);
        }   

        public IActionResult ReturnToOriginalApplication(string returnUrl)
        {
            if (returnUrl != null)
                return Redirect(_redirectSvc.ExtractRedirectUriFromReturnUrl(returnUrl));
            else
                return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public async Task<ActionResult<string>> UserManage([FromQuery] string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);

            return user.UserName.ToString();
        }

    }
}