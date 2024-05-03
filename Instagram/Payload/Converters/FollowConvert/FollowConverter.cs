using Instagram.Context;
using Instagram.Entities;
using Instagram.Payload.DataResponses.Follow;

namespace Instagram.Payload.Converters.FollowConvert
{
    public class FollowConverter
    {
        private readonly AppDbContext _Context;
        public FollowConverter(AppDbContext context)
        {
            _Context = context;
        }
        public ResponseFollow FollowToDTO(int IDUser)
        {
            return new ResponseFollow
            {
                Followers = _Context.RelationShips.Count(x => x.FollowingId == IDUser),
                Following = _Context.RelationShips.Count(x => x.FollowerId == IDUser)
            };
        }
    }
}
