using Instagram.Services.Interface;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Instagram.Controllers
{
    [ApiController]
    public class CollectionController : ControllerBase
    {
        private readonly ICollectionService _collectionService;
        public CollectionController(ICollectionService collectionService)
        {
            _collectionService = collectionService;
        }
        [HttpPost("api/collection/create-collection")]
        public IActionResult CreateCollection([FromForm] string collection_title, [FromForm] string collection_name)
        {
            return Ok(_collectionService.CreateCollection(collection_title, collection_name));
        }
        [HttpPut("api/collection/update-collection")]
        public IActionResult UpdateCollection([FromForm] int idcollection, [FromForm] string collection_title, [FromForm] string collection_name)
        {
            return Ok(_collectionService.UpdateCollection(idcollection, collection_title, collection_name));
        }
        [HttpDelete("api/collection/delete-collection")]
        public IActionResult DeleteCollection([FromForm] int idcollection)
        {
            return Ok(_collectionService.DeleteCollection(idcollection));
        }
        [HttpGet("api/collection/get-collection")]
        public IActionResult GetCollection()
        {
            return Ok(_collectionService.GetCollection());
        }
        [HttpPost("api/collection/add-post-in-collection")]
        public IActionResult AddPostInCollection([FromForm] int idPost, [FromForm] int idCollection)
        {
            return Ok(_collectionService.AddPostInCollection(idPost, idCollection));
        }
        [HttpDelete("api/collection/delete-post-in-collection")]
        public IActionResult DeletePostInCollection([FromForm] int idPost, [FromForm] int idCollection)
        {
            return Ok(_collectionService.DeletePostInCollection(idPost, idCollection));
        }
    }
}
