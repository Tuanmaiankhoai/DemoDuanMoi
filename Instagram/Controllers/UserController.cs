using Instagram.Enumerable;
using Instagram.Payload.DataRequests;
using Instagram.Services.Interface;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Instagram.Controllers
{
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        public UserController(IUserService userService)
        {
            _userService = userService;
        }
        [HttpPost("api/auth/Register")]
        public IActionResult Register([FromForm] RequestRegister request)
        {
            return Ok(_userService.Register(request));
        }
        [HttpPost("api/auth/Login")]
        public IActionResult Login([FromForm] RequestLogin login)
        {
            return Ok(_userService.Login(login));
        }
        //[Authorize(Roles ="Admin")]
        [HttpGet("api/auth/get-all")]
        public IActionResult GetAll()
        {
            return Ok(_userService.GetAll());
        }
        [HttpPut("api/auth/update-user-admin")]
        public IActionResult UpdateUser([FromForm] int id, [FromForm] RequestUser updateUser)
        {
            return Ok(_userService.UpdateUserForAdmin(id, updateUser));
        }
        [HttpPut("api/auth/update-info-myself")]
        public IActionResult UpdateUserForUserLogin([FromForm] RequestUser updateUser)
        {
            return Ok(_userService.UpdateUserForUserLogin(updateUser));
        }
        [HttpDelete("api/auth/delete-user")]
        public IActionResult DeleteUser([FromForm] int id)
        {
            return Ok(_userService.DeleteUser(id));
        }
        [HttpPut("api/auth/set-role")]
        public IActionResult SetRole([FromForm] int id, [FromForm] RoleType role)
        {
            return Ok(_userService.SetRoleForUser(id, role));
        }
        [HttpPost("api/auth/following-user")]
        public IActionResult FolowUser([FromForm] int idUserWantFollow)
        {
            return Ok(_userService.FollowingUser(idUserWantFollow));
        }
        [HttpGet("api/auth/get-relationship-of-user")]
        public IActionResult GetRelationShip()
        {
            return Ok(_userService.GetRelationShipOfUser());
        }
        [HttpPut("api/auth/unfollow-user")]
        public IActionResult UnFollow([FromForm] int idUserWantUnFollow)
        {
            return Ok(_userService.UnFollow(idUserWantUnFollow));
        }
    }
}
