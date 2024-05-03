using Instagram.Entities;

namespace Instagram.Payload.DataResponses.User
{
    public class ResponseUser
    {
        public string Username { get; set; }
        public string RoleName { get; set; }
        public string FullName { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string Email { get; set; }
        public string Avatar { get; set; }
        public string UserStatus { get; set; }
    }
}
