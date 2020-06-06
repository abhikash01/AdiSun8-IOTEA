using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace WebMVC.Infra
{
    public static class API
    {
        public static class JSR
        {
            public static string CallAPI(string baseUri)
            {
                return $"{baseUri}identity";
            }
        }

        public static class ManageUser
        {
            public static string GetUserProfile(string baseUri,string userName)
            {
                return $"{baseUri}User/GetUserProfile?userName={userName}";
            }
            public static string UpdateUserProfile(string baseUri)
            {
                return $"{baseUri}User/UpdateUserProfile";
            }

            public static string UpdatePassword(string baseUri)
            {
                return $"{baseUri}User/UpdatePassword";
            }

        }
    }
}
