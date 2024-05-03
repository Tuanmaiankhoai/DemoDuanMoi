using Instagram.Context;
using Instagram.Entities;
using Instagram.Payload.DataResponses.PostRes;

namespace Instagram.Payload.Converters.PostConvert
{
    public class ComentConverter
    {
        private readonly AppDbContext _context;
        public ComentConverter(AppDbContext context)
        {
            _context = context;
        }
        public ResponseComentPost ComentToDTO(UserCommentPost comentPost)
        {
            return new ResponseComentPost
            {
                UserComent = _context.Users.FirstOrDefault(x=>x.Id == comentPost.UserId).FullName,
                Content = comentPost.Content,
                CreateAt = DateTime.Now,
                NumberOfLikes = comentPost.NumberOfLikes
            };
        }
    }
}
