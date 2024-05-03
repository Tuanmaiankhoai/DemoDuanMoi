using Instagram.Context;
using Instagram.Entities;
using Instagram.Payload.Converters.PostConvert;
using Instagram.Payload.DataRequests;
using Instagram.Payload.DataResponses.CollectionRes;
using Instagram.Payload.DataResponses.Post;
using Instagram.Payload.DataResponses.PostRes;
using Instagram.Payload.Responses;
using Instagram.Services.Interface;
using Microsoft.EntityFrameworkCore;

namespace Instagram.Services.Impelment
{
    public class OtherUserImpactPostService : IOtherUserImpactPostService
    {
        private readonly AppDbContext _Context;
        private readonly PostConverter _postConverter;
        private readonly ReportConverter _reportConverter;
        private readonly IHttpContextAccessor _contextAccessor;
        public OtherUserImpactPostService(AppDbContext context,
                            PostConverter postConverter,
                            IHttpContextAccessor contextAccessor,
                            ReportConverter reportConverter)
        {
            _Context = context;
            _postConverter = postConverter;
            _contextAccessor = contextAccessor;
            _reportConverter = reportConverter;
        }

        //Like hoặc unlike bài viết
        public ResponseObject<ResponsePost> LikeOrUnlikePost(int idpost)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if(!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bạn chưa xác thực hoặc chưa đăng nhập",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var user = _Context.Users.FirstOrDefault(x => x.Id == idUser);
            if (!user.IsActive)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (user.IsLocked)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            var post = _Context.Posts.Include(y => y.UserCommentPosts.Where(c => c.IsActive))
                        .FirstOrDefault(x => x.Id == idpost && x.IsDeleted == false && x.IsActive == true);
            if(post == null)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bài viết này không còn hoạt động hoặc đã bị xóa",
                    Data = null
                };
            }
            var userLikePost = _Context.UserLikePosts.FirstOrDefault(x => x.UserId == idUser && x.PostId == idpost);
            if(userLikePost == null)
            {
                UserLikePost userlikepost = new UserLikePost
                {
                    UserId = idUser,
                    PostId = idpost,
                    LikeTime = DateTime.Now,
                    Unlike = false
                };
                _Context.UserLikePosts.Add(userlikepost);
                post.NumberOfLikes += 1;
                _Context.SaveChanges();
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Like bài viết thành công",
                    Data = _postConverter.PostToDTO(post)
                };
            }
            if (userLikePost.Unlike)
            {
                userLikePost.Unlike = false;
                post.NumberOfLikes += 1;
                _Context.SaveChanges();
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Like bài viết thành công",
                    Data = _postConverter.PostToDTO(post)
                };
            }
            else
            {
                userLikePost.Unlike = true;
                post.NumberOfLikes -= 1;
                _Context.SaveChanges();
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "UnLike bài viết thành công",
                    Data = _postConverter.PostToDTO(post)
                };
            }
        }
        //bình luận vào bài viết
        public ResponseObject<ResponsePost> ComentPost(int idpost, string content)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bạn chưa xác thực hoặc chưa đăng nhập",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var user = _Context.Users.FirstOrDefault(x => x.Id == idUser);
            if (!user.IsActive)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (user.IsLocked)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            var post = _Context.Posts
                       .Include(y=>y.UserCommentPosts.Where(c => c.IsActive))
                       .FirstOrDefault(x => x.Id == idpost && x.IsActive);
            if (post == null)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bài viết này không còn hoạt động hoặc đã bị xóa",
                    Data = null
                };
            }
            UserCommentPost coment = new UserCommentPost
            {
                PostId= idpost,
                UserId = idUser,
                Content = content,
                NumberOfLikes = 0,
                CreateAt = DateTime.Now,
                UpdateAt = DateTime.Now,
                RemoveAt = null,
                IsActive = true,
                IsDeleted = false

            };
            _Context.userCommentPosts.Add(coment);
            post.NumberOfComments += 1;
            _Context.SaveChanges();
            return new ResponseObject<ResponsePost>
            {
                Status = StatusCodes.Status200OK,
                Message = "Coment vào bài viết thành công",
                Data = _postConverter.PostToDTO(post)
            };
        }
        //like hoặc unlike bình luận 
        public ResponseObject<ResponsePost> LikeOrUnlikeComent(int idcoment)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bạn chưa xác thực hoặc chưa đăng nhập",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var user = _Context.Users.FirstOrDefault(x => x.Id == idUser);
            if (!user.IsActive)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (user.IsLocked)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            var coment = _Context.userCommentPosts.FirstOrDefault(x => x.Id == idcoment && x.IsActive);
            if (coment == null)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status404NotFound,
                    Message = "Bình luận này đã bị xóa!",
                    Data = null
                };
            }
            var post = _Context.Posts
                       .Include(y => y.UserCommentPosts.Where(c => c.IsActive))
                       .FirstOrDefault(x => x.Id == coment.PostId && x.IsActive);
            if(post == null)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Không thể thao tác vào bài viết đã bị xóa hoặc không còn hoạt động",
                    Data = null
                };
            }
            var likecoment = _Context.UserLikesComments.FirstOrDefault(x => x.UserCommentPostId == coment.Id && x.UserId == idUser);
            if (likecoment == null)
            {
                UserLikeCommentPost likecomentpost = new UserLikeCommentPost
                {
                    UserId = idUser,
                    UserCommentPostId = coment.Id,
                    LikeTime = DateTime.Now,
                    Unlike = false
                };
                _Context.UserLikesComments.Add(likecomentpost);
                coment.NumberOfLikes += 1;
                _Context.SaveChanges();
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Like coment thành công",
                    Data = _postConverter.PostToDTO(post)
                };
            }
            if(likecoment.Unlike)//unlike = true => đang unlike
            {
                coment.NumberOfLikes += 1;
                likecoment.Unlike = false;
                _Context.SaveChanges();
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Like coment thành công",
                    Data = _postConverter.PostToDTO(post)
                };
            }
            else
            {
                coment.NumberOfLikes -= 1;
                likecoment.Unlike = true;
                _Context.SaveChanges();
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "UnLike coment thành công",
                    Data = _postConverter.PostToDTO(post)
                };
            }
        }
        //Sửa bình luận
        public ResponseObject<ResponsePost> UpdateComent(int idcoment, string content)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bạn chưa xác thực hoặc chưa đăng nhập",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var user = _Context.Users.FirstOrDefault(x => x.Id == idUser);
            if (!user.IsActive)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (user.IsLocked)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            var coment = _Context.userCommentPosts.FirstOrDefault(x=>x.Id == idcoment && x.UserId == idUser && x.IsActive);
            if (coment == null)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bình luận này đã bị xóa hoặc không còn hoạt động",
                    Data = null
                };
            }
            var post = _Context.Posts
                       .Include(y => y.UserCommentPosts.Where(c => c.IsActive))
                       .FirstOrDefault(x => x.Id == coment.PostId && x.IsActive);
            if (post == null)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bài viết này đã bị xóa hoặc không còn hoạt động",
                    Data = null
                };
            }
            coment.Content = content;
            _Context.SaveChanges();
            return new ResponseObject<ResponsePost>
            {
                Status = StatusCodes.Status200OK,
                Message = "Coment vào bài viết thành công",
                Data = _postConverter.PostToDTO(post)
            };
        }
        //Xóa bình luận(chủ bài viết hoặc chủ bình luận mới có thể xóa coment)
        public ResponseObject<ResponsePost> DeleteComent(int idcoment)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bạn chưa xác thực hoặc chưa đăng nhập",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var user = _Context.Users.FirstOrDefault(x => x.Id == idUser);
            if (!user.IsActive)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (user.IsLocked)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            var coment = _Context.userCommentPosts.FirstOrDefault(x => x.Id == idcoment);
            if (!coment.IsActive)
            {
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bình luận đã này bị xóa hoặc gỡ xuống",
                    Data = null
                };
            }
            var idUserPost = _Context.Posts.FirstOrDefault(x => x.Id == coment.PostId).UserId;
            if (coment.UserId == idUser || idUser == idUserPost)
            {
                var postDetail = _Context.Posts
                       .Include(y => y.UserCommentPosts.Where(c => c.IsActive))
                       .FirstOrDefault(x => x.Id == coment.PostId && x.IsActive);
                if (postDetail == null)
                {
                    return new ResponseObject<ResponsePost>
                    {
                        Status = StatusCodes.Status400BadRequest,
                        Message = "Bài viết đã bị xóa hoặc đã bị gỡ xuống!",
                        Data = null
                    };
                }
                coment.IsDeleted = true;
                coment.IsActive = false;
                coment.RemoveAt = DateTime.Now;
                _Context.SaveChanges();
                return new ResponseObject<ResponsePost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Xóa bình luận thành công",
                    Data = _postConverter.PostToDTO(postDetail)
                };
            }
            return new ResponseObject<ResponsePost>
            {
                Status = StatusCodes.Status400BadRequest,
                Message = "Bạn không thể xóa bình luận này",
                Data = null
            };

        }
        //Report bài viết 
        public ResponseObject<ResponseReportPost> ReportPost(RequestReport request)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponseReportPost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bạn chưa xác thực hoặc chưa đăng nhập",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var user = _Context.Users.FirstOrDefault(x => x.Id == idUser);
            if (!user.IsActive)
            {
                return new ResponseObject<ResponseReportPost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (user.IsLocked)
            {
                return new ResponseObject<ResponseReportPost>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            var Post = _Context.Posts.SingleOrDefault(x => x.Id == request.PostId && x.IsActive);
            if(Post == null)
            {
                return new ResponseObject<ResponseReportPost>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bài viết đã bị ẩn hoặc đã bị gỡ xuống!",
                    Data = null
                };
            }
            Report report = new Report
            {
                PostId = request.PostId,
                UserReportId = Post.UserId,
                UserReporterId = idUser,
                ReportType = request.ReportType,
                ReportingReason = request.ReportingReason,
                CreateAt = DateTime.UtcNow,
            };
            _Context.Reports.Add(report);
            _Context.SaveChanges();
            return new ResponseObject<ResponseReportPost>
            {
                Status = StatusCodes.Status200OK,
                Message = "Báo cáo bài viết thành công!",
                Data = _reportConverter.ReportToDTO(report)
            };
        }
        //Get ra toàn bộ báo cáo (admin thì có thể get ra toàn bộ báo cáo của mọi tài khoản)
        public ResponseObject<IEnumerable<ResponseReportPost>> GetAllReport()
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<IEnumerable<ResponseReportPost>>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Bạn chưa xác thực hoặc chưa đăng nhập",
                    Data = null
                };
            }
            if (currentUser.IsInRole("Admin"))
            {
                var Report = _Context.Reports.ToList()
                            .Select(x=> _reportConverter.ReportToDTO(x));
                if(Report == null)
                {
                    return new ResponseObject<IEnumerable<ResponseReportPost>>
                    {
                        Status = StatusCodes.Status404NotFound,
                        Message = "Không có báo cáo nào!",
                        Data = null
                    };
                }
                return new ResponseObject<IEnumerable<ResponseReportPost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Lấy ra danh sách thành công!",
                    Data = Report
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var user = _Context.Users.FirstOrDefault(x => x.Id == idUser);
            if (!user.IsActive)
            {
                return new ResponseObject<IEnumerable<ResponseReportPost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (user.IsLocked)
            {
                return new ResponseObject<IEnumerable<ResponseReportPost>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            var Report2 = _Context.Reports.ToList()
                          .Where(x => x.Id == idUser)
                          .Select(x => _reportConverter.ReportToDTO(x));
            if (Report2 == null)
            {
                return new ResponseObject<IEnumerable<ResponseReportPost>>
                {
                    Status = StatusCodes.Status404NotFound,
                    Message = "Không có báo cáo nào!",
                    Data = null
                };
            }
            return new ResponseObject<IEnumerable<ResponseReportPost>>
            {
                Status = StatusCodes.Status200OK,
                Message = "Lấy ra danh sách thành công!",
                Data = Report2
            };
        }
    }
}
