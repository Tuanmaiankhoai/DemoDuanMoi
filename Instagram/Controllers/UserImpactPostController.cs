using Instagram.Payload.DataRequests;
using Instagram.Services.Interface;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Instagram.Controllers
{
    [ApiController]
    public class UserImpactPostController : ControllerBase
    {
        private readonly IOtherUserImpactPostService _userImpactPostService;
        public UserImpactPostController(IOtherUserImpactPostService userImpactPostService)
        {
            _userImpactPostService = userImpactPostService;
        }
        [HttpPost("api/post/like-or-unlike-post")]
        public IActionResult LikeOrUnlikePost([FromForm] int idpost)
        {
            return Ok(_userImpactPostService.LikeOrUnlikePost(idpost));
        }
        [HttpPost("api/post/coment-post")]
        public IActionResult ComentPost([FromForm] int idpost, [FromForm] string content)
        {
            return Ok(_userImpactPostService.ComentPost(idpost, content));
        }
        [HttpPost("api/post/like-or-unlike-coment")]
        public IActionResult LikeOrUnlikeComent([FromForm] int idcoment)
        {
            return Ok(_userImpactPostService.LikeOrUnlikeComent(idcoment));
        }
        [HttpPut("api/post/update-coment")]
        public IActionResult UpdateComent([FromForm] int idcoment, [FromForm] string content)
        {
            return Ok(_userImpactPostService.UpdateComent(idcoment, content));
        }
        [HttpDelete("api/post/delete-coment")]
        public IActionResult DeleteComent([FromForm] int idcoment)
        {
            return Ok(_userImpactPostService.DeleteComent(idcoment));
        }
        [HttpPost("api/post/report-post")]
        public IActionResult ReportPost([FromForm] RequestReport request)
        {
            return Ok(_userImpactPostService.ReportPost(request));
        }
        [HttpGet("api/post/get-all-post")]
        public IActionResult GetAllPost()
        {
            return Ok(_userImpactPostService.GetAllReport());
        }
    }
}
