using Instagram.Entities;
using Instagram.Enumerable;

namespace Instagram.Payload.DataRequests
{
    public class RequestUser
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string FullName { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string Email { get; set; }
        public IFormFile Avatar { get; set; }
        public bool IsLocked { get; set; } = false;
        public TypeOfUserStatus Status { get; set; }
        public bool IsActive { get; set; } = true;
    }
}
