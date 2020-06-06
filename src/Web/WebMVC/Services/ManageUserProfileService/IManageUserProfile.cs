using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebMVC.Models;

namespace WebMVC.Services.ManageUserProfileService
{
    public interface IManageUserProfile
    {
        Task<ApplicationUser> GetUserProfile(string userName);
        Task UpdateUserProfile(ApplicationUser applicationUser);

        ApplicationUser GetAppUser(ApplicationUser user);

        Task UpdatePassword(ApplicationUser user, ChangePasswordViewModel changePasswordViewModel);
    }
}
