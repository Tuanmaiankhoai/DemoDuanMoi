using Instagram.Entities;
using Instagram.Payload.DataResponses.CollectionRes;
using Instagram.Payload.Responses;

namespace Instagram.Services.Interface
{
    public interface ICollectionService
    {
        ResponseObject<ResponseCollection> CreateCollection(string collectiontitle, string collectionname);
        ResponseObject<ResponseCollection> UpdateCollection(int idcollection, string collectiontitle, string collectionname);
        ResponseObject<IEnumerable<ResponseCollection>> DeleteCollection(int idcollection);
        ResponseObject<IEnumerable<ResponseCollection>> GetCollection();
        ResponseObject<ResponseCollection> AddPostInCollection(int idPost, int idCollection); 
        ResponseObject<IEnumerable<ResponseCollection>> DeletePostInCollection(int idPost, int idCollection);
    }
}
