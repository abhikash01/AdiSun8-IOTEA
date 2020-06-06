using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Threading.Tasks;

namespace WebMVC.Services
{
    public interface IJSRService
    {
        Task<string> CallApi(string userName);
    }
}
