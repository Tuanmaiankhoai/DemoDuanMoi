namespace Instagram.Payload.DataResponses.PostRes
{
    public class ResponseComentPost
    {
        public string UserComent { get; set; }
        public string Content { get; set; }
        public int NumberOfLikes { get; set; }
        public DateTime CreateAt { get; set; }
    }
}
