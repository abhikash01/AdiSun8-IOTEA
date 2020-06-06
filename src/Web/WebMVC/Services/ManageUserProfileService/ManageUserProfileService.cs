using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using WebMVC.Infra;
using WebMVC.Models;

namespace WebMVC.Services.ManageUserProfileService
{
    public class ManageUserProfileService : IManageUserProfile
    {
        private readonly IOptions<AppSettings> _settings;
        private readonly HttpClient _httpClient;

        private readonly string _remoteServiceBaseUrl;
        public ManageUserProfileService(IOptions<AppSettings> settings, HttpClient httpClient)
        {
            _httpClient = httpClient;
            _settings = settings;
            _remoteServiceBaseUrl = $"{_settings.Value.UserManageServiceUrl}";
        }
        public async Task<ApplicationUser> GetUserProfile(string userName)
        {
            var uri = API.ManageUser.GetUserProfile(_remoteServiceBaseUrl,userName);

            var responseString = await _httpClient.GetStringAsync(uri);
            var response = JsonConvert.DeserializeObject<ApplicationUser>(responseString);
            return response;
        }

        public async Task UpdateUserProfile(ApplicationUser user)
        {
            var uri = API.ManageUser.UpdateUserProfile(_remoteServiceBaseUrl);
            var userContent = new StringContent(JsonConvert.SerializeObject(user), System.Text.Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync(uri, userContent);

            response.EnsureSuccessStatusCode();
        }

        public async Task UpdatePassword(ApplicationUser user,ChangePasswordViewModel changePasswordViewModel)
        {
            var uri = API.ManageUser.UpdatePassword(_remoteServiceBaseUrl);
            var userContent = new StringContent(JsonConvert.SerializeObject(user +","+changePasswordViewModel), System.Text.Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync(uri, userContent);
            response.EnsureSuccessStatusCode();

        }

        public ApplicationUser GetAppUser(ApplicationUser user)
        {
            return user;
        }
    }
}
