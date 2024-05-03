using Instagram.Context;
using Instagram.Entities;
using Instagram.Payload.DataResponses.User;

namespace Instagram.Payload.Converters.UserConvert
{
    public class UserConverter
    {
        private AppDbContext _context;
        public UserConverter(AppDbContext context)
        {
            _context = context;
        }
        public ResponseUser EntityToDTO(User user)
        {
            return new ResponseUser
            {
                Username = user.Username,
                RoleName = _context.Roles.SingleOrDefault(x => x.Id == user.RoleId).Name,
                FullName = user.FullName,
                DateOfBirth = user.DateOfBirth,
                Email = user.Email,
                Avatar = user.Avatar,
                UserStatus = _context.UserStatus.SingleOrDefault(x => x.Id == user.UserStatusId).Code
            };
        }
    }
}
