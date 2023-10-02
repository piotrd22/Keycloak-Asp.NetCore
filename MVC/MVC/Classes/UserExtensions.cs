using System.Security.Claims;

namespace MVC.Classes
{
    public static class UserExtensions
    {
        public static bool IsInGroup(this ClaimsPrincipal user, string groupName)
        {
            return user.HasClaim("groups", $"/{groupName}");
        }
    }
}
