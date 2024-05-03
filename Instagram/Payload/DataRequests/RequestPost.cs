using Instagram.Entities;
using Instagram.Enumerable;

namespace Instagram.Payload.DataRequests
{
    public class RequestPost
    {
        public IFormFile ImagePost { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public TypeOfPostStatus PostStatus { get; set; } = TypeOfPostStatus.Public;
    }
}
