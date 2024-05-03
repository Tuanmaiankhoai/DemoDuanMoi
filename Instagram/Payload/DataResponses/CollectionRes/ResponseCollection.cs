using Instagram.Payload.DataResponses.Post;

namespace Instagram.Payload.DataResponses.CollectionRes
{
    public class ResponseCollection
    {
        public string OwnerCollection {  get; set; }
        public string CollectionTitle { get; set; }
        public string CollectionName { get; set; }
        public IEnumerable<ResponsePostCollectionRes> PostCollections { get; set; }
    }
}
