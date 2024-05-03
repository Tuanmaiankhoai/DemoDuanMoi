using Instagram.Context;
using Instagram.Entities;
using Instagram.Payload.Converters.PostConvert;
using Instagram.Payload.DataRequests;
using Instagram.Payload.DataResponses.Post;
using Instagram.Payload.DataResponses.PostRes;
using Instagram.Payload.Responses;
using Instagram.Services.Interface;
using Microsoft.EntityFrameworkCore;
namespace Instagram.Services.Impelment
{
    public class PostService : IPostService
    {
        private readonly AppDbContext _Context;
        private readonly PostConverter _postConverter;
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IWebHostEnvironment _webHostEnvironment;
        public PostService(AppDbContext context, 
                            PostConverter postConverter, 
                            IHttpContextAccessor contextAccessor, 
                            IWebHostEnvironment webHostEnvironment)
        {
            _Context = context;
            _postConverter = postConverter;
            _contextAccessor = contextAccessor;
            _webHostEnvironment = webHostEnvironment;
        }
        //upload file ảnh của post
        private string UploadImageAsync(IFormFile imageFile)
        {
            var uploadPath = Path.Combine(_webHostEnvironment.ContentRootPath, "UploadFiles", "ImagePosts");
            if (!Directory.Exists(uploadPath))
            {
                Directory.CreateDirectory(uploadPath);
            }

            var imageName = Guid.NewGuid().ToString() + Path.GetExtension(imageFile.FileName);
            var imagePath = Path.Combine(uploadPath, imageName);

            using (var stream = new FileStream(imagePath, FileMode.Create))
            {
                imageFile.CopyToAsync(stream);
            }

            return imageName;
        }
        //Tạo bài viết
        public ResponseObject<ResponsePost> CreatePost(RequestPost request)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if(!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponsePost> 
                { 
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực!",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var userlogin = _Context.Users.FirstOrDefault(x=>x.Id == idUser);
            if (!userlogin.IsActive)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (userlogin.IsLocked)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            if (string.IsNullOrEmpty(request.Title)
               || string.IsNullOrEmpty(request.Description)
               || request.ImagePost == null || request.ImagePost.Length == 0)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Vui lòng điền đầy đủ thông tin!",
                    Data = null
                };
            }
            string urlImage = UploadImageAsync(request.ImagePost);
            Post post = new Post
            {
                ImageUrl = urlImage,
                Title = request.Title,
                Description = request.Description,
                CreateAt = DateTime.Now,
                UpdateAt = DateTime.Now,
                UserId = idUser,
                NumberOfLikes = 0,
                NumberOfComments = 0,
                PostStatusId = (int)request.PostStatus,
                IsDeleted = false,
                RemoveAt = null,
                IsActive = true
            };
            _Context.Posts.Add(post);
            _Context.SaveChanges();
            return new ResponseObject<ResponsePost>
            {
                Status = StatusCodes.Status200OK,
                Message = "Đăng bài thành công!",
                Data = _postConverter.PostToDTO(post)
            };
        }
        //Sửa bài viết
        public ResponseObject<ResponsePost> UpdatePost(int idPost, RequestPost request)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực!",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var userlogin = _Context.Users.FirstOrDefault(x => x.Id == idUser);
            if (!userlogin.IsActive)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (userlogin.IsLocked)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            if (string.IsNullOrEmpty(request.Title)
               || string.IsNullOrEmpty(request.Description)
               || request.ImagePost == null || request.ImagePost.Length == 0)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Vui lòng điền đầy đủ thông tin!",
                    Data = null
                };
            }
            string urlImage = UploadImageAsync(request.ImagePost);
            var postUser = _Context.Posts
                           .Include(y=>y.UserCommentPosts.Where(c => c.IsActive))
                           .FirstOrDefault(x => x.Id == idPost && x.UserId == idUser && x.IsActive);
            if(postUser == null)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status404NotFound,
                    Message = "Bài viết này không tồn tại hoặc đã bị xóa!",
                    Data = null
                };
            }
            postUser.ImageUrl = urlImage;
            postUser.Title = request.Title;
            postUser.Description = request.Description;
            postUser.UpdateAt = DateTime.Now;
            postUser.PostStatusId = (int)request.PostStatus;
            _Context.SaveChanges();
            return new ResponseObject<ResponsePost>
            {
                Status = StatusCodes.Status200OK,
                Message = "Cập nhật bài viết thành công!",
                Data = _postConverter.PostToDTO(postUser)
            };
        }
        //Xóa bài viết
        public ResponseObject<IEnumerable<ResponsePost>> DeletePost(int idPost)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực!",
                    Data = null
                };
            }
            if (currentUser.IsInRole("Admin"))
            {
                var postA = _Context.Posts.FirstOrDefault(x => x.Id == idPost && !x.IsDeleted);
                if (postA == null)
                {
                    return new ResponseObject<IEnumerable<ResponsePost>>
                    {
                        Status = StatusCodes.Status404NotFound,
                        Message = "Bài viết này đã được chủ post gỡ hoặc đã bị quản trị viên gỡ",
                        Data = null
                    };
                }
                postA.IsDeleted = true;
                postA.RemoveAt = DateTime.Now;
                postA.IsActive = false;
                _Context.SaveChanges();
                var postcollectionA = _Context.PostCollections.SingleOrDefault(x => x.PostId == idPost);
                if (postcollectionA != null)
                {
                    _Context.PostCollections.Remove(postcollectionA);
                    _Context.SaveChanges();
                }
                var listPostA = _Context.Posts
                                .Include(y=>y.UserCommentPosts.Where(c => c.IsActive)).ToList()
                                .Select(x => _postConverter.PostToDTO(x));
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Xóa bài viết thành công!",
                    Data = listPostA
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var userlogin = _Context.Users.FirstOrDefault(x => x.Id == idUser);
            if (!userlogin.IsActive)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (userlogin.IsLocked)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            var post = _Context.Posts.FirstOrDefault(x => x.Id == idPost && x.UserId == idUser && !x.IsDeleted);
            if (post == null)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status404NotFound,
                    Message = "Bài viết này đã được chủ post gỡ hoặc đã bị quản trị viên gỡ",
                    Data = null
                };
            }
            post.IsDeleted = true;
            post.RemoveAt = DateTime.Now;
            post.IsActive = false;
            _Context.SaveChanges();
            var postcollection = _Context.PostCollections.SingleOrDefault(x => x.PostId == idPost);
            if (postcollection != null)
            {
                _Context.PostCollections.Remove(postcollection);
                _Context.SaveChanges();
            }
            var listPost = _Context.Posts
                            .Include(y => y.UserCommentPosts.Where(c => c.IsActive)).ToList()
                            .Where(x=>x.UserId == idUser && x.IsActive)
                            .Select(x => _postConverter.PostToDTO(x))
                            .AsQueryable();
            return new ResponseObject<IEnumerable<ResponsePost>>
            {
                Status = StatusCodes.Status200OK,
                Message = "Xóa bài viết thành công!",
                Data = listPost
            };
        }
        //lấy ra toàn bộ bài viết (bộ lọc: chưa xóa, đã xóa, bị ẩn)
        public ResponseObject<IEnumerable<ResponsePost>> GetAllPost(bool? isdelete = false, bool? isactive = true)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực!",
                    Data = null
                };
            }
            if (currentUser.IsInRole("Admin"))
            {
                var postA = _Context.Posts
                            .Include(y => y.UserCommentPosts.Where(c => c.IsActive)).ToList()
                            .Where(x=>x.IsDeleted == isdelete || x.IsActive == isactive);
                if (postA == null)
                {
                    return new ResponseObject<IEnumerable<ResponsePost>>
                    {
                        Status = StatusCodes.Status404NotFound,
                        Message = "Danh bài viết sách trống!",
                        Data = null
                    };
                }
                var listPostA = postA.Select(x => _postConverter.PostToDTO(x));
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Lấy danh sách bài viết thành công!",
                    Data = listPostA
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var userlogin = _Context.Users.FirstOrDefault(x => x.Id == idUser);
            if (!userlogin.IsActive)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (userlogin.IsLocked)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            var post = _Context.Posts
                        .Include(y=>y.UserCommentPosts.Where(c => c.IsActive)).ToList()
                        .Where(x=>(x.UserId == idUser && x.IsDeleted == isdelete) || (x.UserId == idUser && x.IsActive == isactive));
            if (post == null)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status404NotFound,
                    Message = "Danh sách bài viết trống!",
                    Data = null
                };
            }
            var listPost = post.Select(x => _postConverter.PostToDTO(x));
            return new ResponseObject<IEnumerable<ResponsePost>>
            {
                Status = StatusCodes.Status200OK,
                Message = "Lấy danh sách bài viết thành công!",
                Data = listPost
            };
        }
        //Xem danh sách bộ sưu tập của người khác
        public ResponseObject<IEnumerable<ResponsePost>> GetAllPostOfOtherUser(int idOtherUser)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực!",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var userlogin = _Context.Users.FirstOrDefault(x => x.Id == idUser);
            if (!userlogin.IsActive)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (userlogin.IsLocked)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            if (_Context.Users.Any(x=>x.Id == idOtherUser))
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status404NotFound,
                    Message = "Không tìm thấy người dùng này",
                    Data = null
                };
            }
            var post = _Context.Posts
                        .Include(y => y.UserCommentPosts.Where(c => c.IsActive)).ToList()
                        .Where(x => x.UserId == idOtherUser && x.IsActive);
            if (post == null)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status404NotFound,
                    Message = "Danh sách bài viết trống!",
                    Data = null
                };
            }
            var listPost = post.Select(x => _postConverter.PostToDTO(x));
            return new ResponseObject<IEnumerable<ResponsePost>>
            {
                Status = StatusCodes.Status200OK,
                Message = "Lấy danh sách bài viết thành công!",
                Data = listPost
            };
        }
        //Khôi phục bài viết (chỉ admin)
        public ResponseObject<ResponsePost> RestorPost(int idPost)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực!",
                    Data = null
                };
            }
            if (currentUser.IsInRole("Admin"))
            {
                var post = _Context.Posts.FirstOrDefault(x => x.Id == idPost);
                if (post == null)
                {
                    return new ResponseObject<ResponsePost>
                    {
                        Status = StatusCodes.Status404NotFound,
                        Message = "Bài viết này không tồn tại trong cơ sở dữ liệu!",
                        Data = null
                    };
                }
                if(!_Context.Users.Any(x=>x.Id == post.UserId))
                {
                    return new ResponseObject<ResponsePost>
                    {
                        Status = StatusCodes.Status404NotFound,
                        Message = "Không thể khôi phục bài viết của người dùng đã bị xóa!",
                        Data = null
                    };
                }
                if(!post.IsDeleted)
                {
                    return new ResponseObject<ResponsePost>
                    {
                        Status = StatusCodes.Status400BadRequest,
                        Message = "Không thể khôi phục bài viết không bị xóa!",
                        Data = null
                    };
                }
                else
                {
                    post.IsDeleted = false;
                    post.RemoveAt = null;
                    post.IsActive = true;
                    _Context.SaveChanges();
                    return new ResponseObject<ResponsePost>
                    {
                        Status = StatusCodes.Status401Unauthorized,
                        Message = "Khôi phục bài viết thành công!",
                        Data = _postConverter.PostToDTO(post)
                    };
                }
            }
            return new ResponseObject<ResponsePost>
            {
                Status = StatusCodes.Status401Unauthorized,
                Message = "Bạn không đủ quyền để thực hiện chức năng này!",
                Data = null
            };
        }
        //Ẩn bài viết (dừng hoạt động)
        public ResponseObject<IEnumerable<ResponsePost>> HiddenPost(int idPost)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực!",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var userlogin = _Context.Users.FirstOrDefault(x => x.Id == idUser);
            if (!userlogin.IsActive)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (userlogin.IsLocked)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            var post = _Context.Posts.FirstOrDefault(x => x.Id == idPost && x.UserId == idUser && x.IsActive);
            if (post == null)
            {
                return new ResponseObject<IEnumerable<ResponsePost>>
                {
                    Status = StatusCodes.Status404NotFound,
                    Message = "Bài viết này đã bị gỡ hoặc ẩn",
                    Data = null
                };
            }
            post.IsActive = true;
            _Context.SaveChanges();
            var postcollection = _Context.PostCollections.SingleOrDefault(x => x.PostId == idPost);
            if (postcollection != null)
            {
                _Context.PostCollections.Remove(postcollection);
                _Context.SaveChanges();
            }
            var listPost = _Context.Posts
                            .Include(y => y.UserCommentPosts.Where(c => c.IsActive)).ToList()
                            .Where(x => x.UserId == idUser && x.IsActive)
                            .Select(x => _postConverter.PostToDTO(x));
            return new ResponseObject<IEnumerable<ResponsePost>>
            {
                Status = StatusCodes.Status200OK,
                Message = "Ẩn bài viết thành công!",
                Data = listPost
            };
        }
    }
}
