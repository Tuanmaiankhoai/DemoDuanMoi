namespace Instagram.Entities
{
    public class UserCommentPost:Base
    {
        public int PostId { get; set; }
        public Post? Post { get; set; }
        public int UserId { get; set; }
        public User? User { get; set; }
        public string Content { get; set; }
        public int NumberOfLikes { get; set; }
        public DateTime CreateAt { get; set; }
        public DateTime UpdateAt { get; set; }
        public DateTime? RemoveAt { get; set; } = null;
        public bool IsDeleted { get; set; } = false;
        public bool IsActive { get; set; } = true;

    }
}
