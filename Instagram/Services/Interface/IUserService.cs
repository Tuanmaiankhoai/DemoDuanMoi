using Instagram.Entities;
using Instagram.Enumerable;
using Instagram.Payload.DataRequests;
using Instagram.Payload.DataResponses.Follow;
using Instagram.Payload.DataResponses.User;
using Instagram.Payload.Responses;

namespace Instagram.Services.Interface
{
    public interface IUserService
    {
        ResponseObject<ResponseUser> Register(RequestRegister request);
        ResponseObject<ResponseToken> Login(RequestLogin request);
        ResponseToken GenerateAccessToken(User user);
        ResponseToken RenewAccessToken(Request_RenewAccessToken request);
        ResponseObject<IQueryable<ResponseUser>> GetAll();
        ResponseObject<ResponseUser> UpdateUserForAdmin(int id, RequestUser Request);
        ResponseObject<ResponseUser> UpdateUserForUserLogin(RequestUser Request);
        ResponseObject<IQueryable<ResponseUser>> DeleteUser(int id);
        ResponseObject<ResponseUser> SetRoleForUser(int id, RoleType role);
        ResponseObject<ResponseFollow> FollowingUser(int idUserWantFollow);
        ResponseObject<ResponseFollow> GetRelationShipOfUser();
        ResponseObject<ResponseFollow> UnFollow(int idUserWantUnFollow);
    }
}
