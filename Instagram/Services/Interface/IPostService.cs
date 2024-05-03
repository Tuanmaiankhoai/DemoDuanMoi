using Instagram.Entities;
using Instagram.Payload.DataRequests;
using Instagram.Payload.DataResponses.Post;
using Instagram.Payload.Responses;
using System.Collections;

namespace Instagram.Services.Interface
{
    public interface IPostService
    {
        ResponseObject<ResponsePost> CreatePost(RequestPost request);
        ResponseObject<ResponsePost> UpdatePost(int idPost, RequestPost request);
        ResponseObject<ResponsePost> RestorPost(int idPost);
        ResponseObject<IEnumerable<ResponsePost>> DeletePost(int idPost);
        ResponseObject<IEnumerable<ResponsePost>> GetAllPost(bool? isdelete = false, bool? isactive = true);
        ResponseObject<IEnumerable<ResponsePost>> GetAllPostOfOtherUser(int idOtherUser);
        ResponseObject<IEnumerable<ResponsePost>> HiddenPost(int idPost);
    }
}
