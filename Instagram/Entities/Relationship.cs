using System.ComponentModel.DataAnnotations.Schema;

namespace Instagram.Entities
{
    public class Relationship:Base
    {
        [ForeignKey("Follower")]
        public int FollowerId { get; set; } 
        public User? Follower { get; set; }
        [ForeignKey("Following")]
        public int FollowingId { get; set; }
        public User? Following { get; set; }
    }
}
