using Instagram.Payload.DataRequests;
using Instagram.Payload.DataResponses.Post;
using Instagram.Payload.DataResponses.PostRes;
using Instagram.Payload.Responses;
using System.Collections;

namespace Instagram.Services.Interface
{
    public interface IOtherUserImpactPostService
    {
        ResponseObject<ResponsePost> LikeOrUnlikePost(int idpost);
        ResponseObject<ResponsePost> ComentPost(int idpost, string content);
        ResponseObject<ResponsePost> LikeOrUnlikeComent(int idcoment);
        ResponseObject<ResponsePost> UpdateComent(int idcoment, string content);
        ResponseObject<ResponsePost> DeleteComent(int idcoment);
        ResponseObject<ResponseReportPost> ReportPost(RequestReport request);
        ResponseObject<IEnumerable<ResponseReportPost>> GetAllReport();
    }
}
