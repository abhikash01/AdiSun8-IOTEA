using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using WebMVC.Infra;

namespace WebMVC.Services
{
    public class JSRService : IJSRService
    {
        private readonly IOptions<AppSettings> _settings;
        private readonly HttpClient _httpClient;

        private readonly string _remoteServiceBaseUrl;

        public JSRService(HttpClient httpClient, IOptions<AppSettings> settings)
        {
            _httpClient = httpClient;
            _settings = settings;

            _remoteServiceBaseUrl = $"{_settings.Value.JSRApiurl}";
        }

        public async Task<string> CallApi(string userName)
        {
            var uri = API.JSR.CallAPI(_remoteServiceBaseUrl);

            var response = await _httpClient.GetStringAsync(uri);

            return response;
        }


    }
}
