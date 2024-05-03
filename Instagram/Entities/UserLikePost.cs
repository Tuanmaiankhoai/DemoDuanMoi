namespace Instagram.Entities
{
    public class UserLikePost:Base
    {
        public int UserId { get; set; }
        public User? User { get; set; }
        public int PostId { get; set; }
        public Post? Post { get; set; }
        public DateTime LikeTime { get; set; }
        public bool Unlike { get; set; }
    }
}
