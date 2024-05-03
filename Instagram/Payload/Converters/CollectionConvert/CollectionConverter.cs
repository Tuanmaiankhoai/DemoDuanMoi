using Instagram.Context;
using Instagram.Entities;
using Instagram.Payload.DataResponses.CollectionRes;

namespace Instagram.Payload.Converters.CollectionConver
{
    public class CollectionConverter
    {
        private readonly AppDbContext _context;
        private readonly PostCollectionConverter _postCollectionConverter;
        public CollectionConverter(AppDbContext context, PostCollectionConverter postCollectionConverter)
        {
            _context = context;
            _postCollectionConverter = postCollectionConverter;
        }
        public ResponseCollection collectionToDTO(Collection collection)
        {
            return new ResponseCollection
            {
                OwnerCollection = _context.Users.FirstOrDefault(x => x.Id == collection.UserId).Username,
                CollectionName = collection.CollectionName,
                CollectionTitle = collection.CollectionTitle,
                PostCollections = _context.PostCollections.ToList()
                                    .Where(x => x.CollectionId == collection.Id)
                                    .Select(x => _postCollectionConverter.PostCollectionToDTO(x))
                                    .AsQueryable()
            };
        }
    }
}
