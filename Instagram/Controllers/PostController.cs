using Instagram.Payload.DataRequests;
using Instagram.Services.Interface;
using Microsoft.AspNetCore.Mvc;

namespace Instagram.Controllers
{
    [ApiController]
    public class PostController : ControllerBase
    {
        private readonly IPostService _userPostService;
        public PostController(IPostService userPostService)
        {
            _userPostService = userPostService;
        }
        [HttpPost("api/post/create-post")]
        public IActionResult CreatePost([FromForm] RequestPost requestPost)
        {
            return Ok(_userPostService.CreatePost(requestPost));
        }
        [HttpPut("api/post/update-post")]
        public IActionResult UpdatePost([FromForm] int idPost, [FromForm] RequestPost requestPost)
        {
            return Ok(_userPostService.UpdatePost(idPost, requestPost));
        }
        [HttpDelete("api/post/delete-post")]
        public IActionResult DeletePost([FromForm] int idPost)
        {
            return Ok(_userPostService.DeletePost(idPost));
        }
        [HttpGet("api/post/get-all-post")]
        public IActionResult GetAllPost([FromForm] bool isdelete, [FromForm] bool isactive)
        {
            return Ok(_userPostService.GetAllPost(isdelete, isactive));
        }
        [HttpGet("api/post/get-post-of-other-user")]
        public IActionResult GetAllPostOfOtherUser([FromForm] int idOtherUser)
        {
            return Ok(_userPostService.GetAllPostOfOtherUser(idOtherUser));
        }
        [HttpPut("api/post/restore-post")]
        public IActionResult RestorePost([FromForm] int idpost)
        {
            return Ok(_userPostService.RestorPost(idpost));
        }
        [HttpPut("api/post/hidden-post")]
        public IActionResult HiddenPost([FromForm] int idpost)
        {
            return Ok(_userPostService.HiddenPost(idpost));
        }
    }
}
