namespace Instagram.Entities
{
    public class PostCollection:Base
    {
        public int PostId { get; set; }
        public Post? Post { get; set; }
        public int CollectionId { get; set; }
        public Collection? Collection { get; set; }
    }
}
