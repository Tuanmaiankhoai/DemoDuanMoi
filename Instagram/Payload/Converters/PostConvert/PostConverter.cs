using Instagram.Context;
using Instagram.Entities;
using Instagram.Payload.DataResponses.Post;

namespace Instagram.Payload.Converters.PostConvert
{
    public class PostConverter
    {
        private readonly AppDbContext _context;
        private readonly ComentConverter _comentconverter;
        public PostConverter(AppDbContext context, ComentConverter comentconverter)
        {
            _context = context;
            _comentconverter = comentconverter;
        }
        public ResponsePost PostToDTO(Post post)
        {
            return new ResponsePost
            {
                ImageUrl = post.ImageUrl,
                Title = post.Title,
                Description = post.Description,
                CreateAt = post.CreateAt,
                OwnerPost = _context.Users.FirstOrDefault(x => x.Id == post.UserId).Username,
                NumberOfLikes = post.NumberOfLikes,
                NumberOfComments = post.NumberOfComments,
                PostStatus = _context.PostStatus.FirstOrDefault(y => y.Id == post.PostStatusId).Name,
                userCommentPosts = _context.userCommentPosts.ToList()
                                   .Where(x=>x.PostId == post.Id)
                                   .Select(x=> _comentconverter.ComentToDTO(x))
            };
        }
    }
}
