namespace Instagram.Entities
{
    public class Post:Base
    {
        public string ImageUrl { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public DateTime CreateAt { get; set; }
        public DateTime UpdateAt { get; set; }
        public int UserId { get; set; }
        public User? User { get; set; }
        public int NumberOfLikes { get; set; }
        public int NumberOfComments { get; set; }
        public int PostStatusId { get; set; }
        public PostStatus? PostStatus { get; set; }
        public bool IsDeleted { get; set; } = false;
        public DateTime? RemoveAt { get; set; }
        public bool IsActive { get; set; } = true;
        public IEnumerable<UserCommentPost> UserCommentPosts { get; set;}
    }
}
