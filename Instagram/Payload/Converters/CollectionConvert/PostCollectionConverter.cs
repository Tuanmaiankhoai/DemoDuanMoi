using Instagram.Context;
using Instagram.Entities;
using Instagram.Payload.DataResponses.CollectionRes;

namespace Instagram.Payload.Converters.CollectionConver
{
    public class PostCollectionConverter
    {
        private readonly AppDbContext _context;
        public PostCollectionConverter(AppDbContext context)
        {
            _context = context;
        }
        public ResponsePostCollectionRes PostCollectionToDTO(PostCollection postCollection)
        {
            return new ResponsePostCollectionRes
            {
                PostTitle = _context.Posts.SingleOrDefault(x=>x.Id == postCollection.PostId).Title,
                CollectionTitle = _context.Collections.SingleOrDefault(x=>x.Id == postCollection.CollectionId).CollectionTitle,
            };
        }
    }
}
