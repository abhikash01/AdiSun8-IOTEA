using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using WebMVC.Infra;
using WebMVC.Models;
using WebMVC.Services;
using WebMVC.Services.ManageUserProfileService;

namespace WebMVC
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews()
                    .Services
                    .AddCustomMvc(Configuration)
                    .AddHttpClientServices(Configuration);

            JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

            services.AddControllers();

            services.AddCustomAuthentication(Configuration);

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Remove("sub");
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            var pathBase = Configuration["PATH_BASE"];

            if (!string.IsNullOrEmpty(pathBase))
            {
                app.UsePathBase(pathBase);
            }


            app.UseStaticFiles();
            app.UseSession();

            //if testing add to bypass Authentication middleware add code here

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapControllers();

                // .RequireAuthorization(); to make Authorization compulsory for whole app
            });
        }


    }
    static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddHttpClientServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services.AddTransient<HttpClientAuthorizationDelegatingHandler>();
            services.AddTransient<HttpClientRequestIdDelegatingHandler>();

            //add 5 min as the lifetime for each HttpMessageHandler in the pool
            services.AddHttpClient("extendedhandlerlifetime").SetHandlerLifetime(TimeSpan.FromMinutes(5));

            services.AddHttpClient<IJSRService, JSRService>()
                .AddHttpMessageHandler<HttpClientAuthorizationDelegatingHandler>()
                 .AddHttpMessageHandler<HttpClientRequestIdDelegatingHandler>();

            services.AddHttpClient<IManageUserProfile, ManageUserProfileService>()
                .AddHttpMessageHandler<HttpClientAuthorizationDelegatingHandler>()
                 .AddHttpMessageHandler<HttpClientRequestIdDelegatingHandler>();

            services.AddTransient<IIdentityParser<ApplicationUser>, IdentityParser>();

            return services;
        }

        public static IServiceCollection AddCustomMvc(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddOptions();
            services.Configure<AppSettings>(configuration);
            services.AddSession();

            return services;

        }

        public static IServiceCollection AddCustomAuthentication(this IServiceCollection services, IConfiguration configuration)
        {

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = "oidc";
            })
                .AddCookie(setup =>
                {
                    setup.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                    setup.Cookie.Name = "mvcC";
                })
                .AddOpenIdConnect("oidc", options =>
                {
                    options.Authority = "http://localhost:5000";
                    options.RequireHttpsMetadata = false;

                    options.ClientId = "WebMVC";
                    options.ClientSecret = "WebMVC";

                    options.ResponseType = "code";
                    options.UsePkce = true;

                    options.SignedOutRedirectUri = "http://localhost:5002";

                    options.Scope.Clear();
                    options.Scope.Add("openid");
                    options.Scope.Add("profile");
                    options.Scope.Add("email");
                    options.Scope.Add("JSR.full_access");
                    options.Scope.Add("offline_access");

                    options.ClaimActions.MapJsonKey("website", "website");

                    // keeps id_token smaller
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.SaveTokens = true;


                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = JwtClaimTypes.Name,
                        RoleClaimType = JwtClaimTypes.Role,
                    };

                    //options.Events = new OpenIdConnectEvents
                    //{
                    //    OnRemoteFailure = context => {
                    //        context.Response.Redirect("/");
                    //        context.HandleResponse();

                    //        return Task.FromResult(0);
                    //    }
                    //};
                });

            return services;
        }
    }
}
