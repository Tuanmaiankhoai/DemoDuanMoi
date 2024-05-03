using Instagram.Entities;

namespace Instagram.Payload.DataRequests
{
    public class RequestRegister
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string FullName { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string Email { get; set; }
        public IFormFile Avatar { get; set; }
    }
}
