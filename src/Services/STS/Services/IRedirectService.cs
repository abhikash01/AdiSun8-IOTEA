using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace STS.Services
{
    public interface IRedirectService
    {
        string ExtractRedirectUriFromReturnUrl(string url);

    }
}
