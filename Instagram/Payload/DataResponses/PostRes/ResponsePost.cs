using Instagram.Entities;
using Instagram.Enumerable;
using Instagram.Payload.DataResponses.PostRes;

namespace Instagram.Payload.DataResponses.Post
{
    public class ResponsePost
    {
        public string ImageUrl { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public DateTime CreateAt { get; set; }
        public string OwnerPost { get; set; }
        public int NumberOfLikes { get; set; }
        public int NumberOfComments { get; set; }
        public string PostStatus { get; set; }
        public IEnumerable<ResponseComentPost> userCommentPosts { get; set; }
    }
}
