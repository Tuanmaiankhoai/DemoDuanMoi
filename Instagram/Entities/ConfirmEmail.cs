namespace Instagram.Entities
{
    public class ConfirmEmail:Base
    {
        public int UserId { get; set; }
        public User? User { get; set; }
        public DateTime ExpiredTime { get; set; }
        public string ConfirmCode { get; set; }
        public bool Confirmed { get; set; } = false;
    }
}
