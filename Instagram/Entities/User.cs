namespace Instagram.Entities
{
    public class User:Base
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public int RoleId { get; set; }
        public Role? Role { get; set; }
        public string FullName { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string Email { get; set; }
        public string Avatar { get; set; }
        public bool IsLocked { get; set; }
        public int UserStatusId { get; set; }
        public UserStatus? UserStatus { get; set; }
        public bool IsActive { get; set; }
    }
}
