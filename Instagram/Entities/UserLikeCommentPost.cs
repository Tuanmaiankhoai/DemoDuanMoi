namespace Instagram.Entities
{
    public class UserLikeCommentPost:Base
    {
        public int UserId { get; set; }
        public User User { get; set; }
        public int UserCommentPostId { get; set; }
        public UserCommentPost UserCommentPost { get; set; }
        public DateTime LikeTime { get; set; }
        public bool Unlike { get; set; } = false;
    }
}
