using Azure.Core;
using Instagram.Context;
using Instagram.Entities;
using Instagram.Enumerable;
using Instagram.Payload.Converters.FollowConvert;
using Instagram.Payload.Converters.UserConvert;
using Instagram.Payload.DataRequests;
using Instagram.Payload.DataResponses.Follow;
using Instagram.Payload.DataResponses.User;
using Instagram.Payload.Responses;
using Instagram.Services.Interface;
using Instagram.Validates;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.NetworkInformation;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;
using BCryptNet = BCrypt.Net.BCrypt;

namespace Instagram.Services.Impelment
{
    public class UserService : IUserService
    {
        #region private
        private readonly AppDbContext _Context;
        private readonly UserConverter _userConverter;
        private readonly FollowConverter _FlConverter;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IWebHostEnvironment _webHostEnvironment;
        #endregion
        #region Khaibáo
        public UserService(AppDbContext context, 
                            UserConverter userConverter, 
                            FollowConverter flConverter,
                            IConfiguration configuration, 
                            IHttpContextAccessor contextAccessor, 
                            IWebHostEnvironment webHostEnvironment)
        {
            _Context = context;
            _userConverter = userConverter;
            _FlConverter = flConverter;
            _configuration = configuration;
            _contextAccessor = contextAccessor;
            _webHostEnvironment = webHostEnvironment;
        }
        #endregion
        #region Func
        //Tạo refeshToken ngẫu nhiên
        private string GenerateRefeshToken()
        {
            var random = new byte[32];
            using (var item = RandomNumberGenerator.Create())
            {
                item.GetBytes(random);
                return Convert.ToBase64String(random);
            }
        }
        //Tạo AccessToken
        public ResponseToken GenerateAccessToken(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var secretKeyBytes = Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:SecretKey").Value);
            var role = _Context.Roles.FirstOrDefault(x=>x.Id == user.RoleId);
            var tokenDesciption = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("ID",user.Id.ToString()),
                    new Claim("Email",user.Email),
                    new Claim(ClaimTypes.Role,role.Code),
                }),
                Expires = DateTime.Now.AddHours(4),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secretKeyBytes), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = jwtTokenHandler.CreateToken(tokenDesciption);
            var accessToken = jwtTokenHandler.WriteToken(token);
            var refeshToken = GenerateRefeshToken();
            RefeshToken rf = new RefeshToken
            {
                Token = refeshToken,
                ExpiredTime = DateTime.Now.AddDays(1),
                UserId = user.Id,
            };
            _Context.RefreshTokens.Add(rf);
            _Context.SaveChanges();
            ResponseToken result = new ResponseToken
            {
                AccessToken = accessToken,
                RefeshToken = refeshToken
            };
            return result;
        }
        //Đăng nhập
        public ResponseObject<ResponseToken> Login(RequestLogin request)
        {
            if (string.IsNullOrEmpty(request.UserName)||string.IsNullOrEmpty(request.Password))
            {
                return new ResponseObject<ResponseToken>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Vui lòng điền đầy đủ thông tin!",
                    Data = null
                };
            }
            var user = _Context.Users.FirstOrDefault(x => x.Username.Equals(request.UserName));
            if (user == null)
            {
                return new ResponseObject<ResponseToken>
                {
                    Status = StatusCodes.Status404NotFound,
                    Message = "Người dùng không tồn tại!",
                    Data = null
                };
            }
            bool checkPass = BCryptNet.Verify(request.Password, user.Password);
            if(!checkPass)
            {
                return new ResponseObject<ResponseToken>
                {
                    Status = StatusCodes.Status404NotFound,
                    Message = "Mật khẩu không chính xác!",
                    Data = null
                };
            }
            if(!user.IsActive)
            {
                return new ResponseObject<ResponseToken>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (user.IsLocked)
            {
                return new ResponseObject<ResponseToken>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = GenerateAccessToken(user)
                };
            }
            return new ResponseObject<ResponseToken>
            {
                Status = StatusCodes.Status200OK,
                Message = "Đăng nhập thành công!",
                Data = GenerateAccessToken(user)
            };
        }
        //Làm mới Accesstoken
        public ResponseToken RenewAccessToken(Request_RenewAccessToken request)
        {
            throw new NotImplementedException();
        }
        //uploadfile
        private string UploadImageAsync(IFormFile imageFile)
        {
            var uploadPath = Path.Combine(_webHostEnvironment.ContentRootPath, "UploadFiles", "Avatars");
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
        // Đăng ký 
        public ResponseObject<ResponseUser> Register(RequestRegister request)
        {
            if (string.IsNullOrEmpty(request.Username)
                || string.IsNullOrEmpty(request.FullName)
                || string.IsNullOrEmpty(request.Email)
                || string.IsNullOrEmpty(request.Password)
                || request.Avatar == null || request.Avatar.Length == 0)
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Vui lòng điền đẩy đủ thông tin!",
                    Data = null
                };
            }
            if (_Context.Users.Any(x => x.Username.ToLower().Equals(request.Username.ToLower())))
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Tài khoản đã tồn tại!",
                    Data = null
                };
            }
            if (_Context.Users.Any(x => x.Email.ToLower().Equals(request.Email.ToLower())))
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Email đã tồn tại!",
                    Data = null
                };
            }
            if (!ValidateEmail.IsEmail(request.Email))
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Eamil không đúng định dạng!",
                    Data = null
                };
            }
            var user = new User();
            user.Username = request.Username;
            user.FullName = request.FullName;
            user.Email = request.Email;
            user.Password = BCryptNet.HashPassword(request.Password);
            user.RoleId = 1;
            var avatarName = UploadImageAsync(request.Avatar);
            user.Avatar = avatarName;
            user.DateOfBirth = request.DateOfBirth;
            user.UserStatusId = 2;
            user.IsActive = true;
            user.IsLocked = false;
            _Context.Users.Add(user);
            _Context.SaveChanges();
            return new ResponseObject<ResponseUser>
            {
                Status = StatusCodes.Status200OK,
                Message = "Đăng ký thành công!",
                Data = _userConverter.EntityToDTO(user)
            };
        }
        //Get All (Chỉ Admin)
        public ResponseObject<IQueryable<ResponseUser>> GetAll()
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<IQueryable<ResponseUser>>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa được xác thực!",
                    Data = null
                };
            }
            if (currentUser.IsInRole("Admin"))
            {
                var userList = _Context.Users.ToList().Select(x => _userConverter.EntityToDTO(x)).AsQueryable();
                if (!userList.Any())
                {
                    return new ResponseObject<IQueryable<ResponseUser>>
                    {
                        Status = StatusCodes.Status404NotFound,
                        Message = "Danh sách trống!",
                        Data = null
                    };
                }
                return new ResponseObject<IQueryable<ResponseUser>>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Thực hiện thao tác thành công!",
                    Data = userList
                };
            }
            return new ResponseObject<IQueryable<ResponseUser>>
            {
                Status = StatusCodes.Status401Unauthorized,
                Message = "Bạn không đủ quyền hạn để thực hiện thao tác này!",
                Data = null
            };
        }
        //Sửa thông tin người dùng (Không sửa Role)
        public ResponseObject<ResponseUser> UpdateUserForAdmin(int id, RequestUser Request)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa được xác thực!",
                    Data = null
                };
            }
            if (currentUser.IsInRole("admin"))
            {
                var user = _Context.Users.SingleOrDefault(x => x.Id == id);
                if (user is null)
                {
                    return new ResponseObject<ResponseUser>
                    {
                        Status = StatusCodes.Status404NotFound,
                        Message = "Không tìm thấy người dùng này!",
                        Data = null
                    };
                }
                if (string.IsNullOrEmpty(Request.Username)
                    || string.IsNullOrEmpty(Request.Password)
                    || string.IsNullOrEmpty(Request.FullName)
                    || string.IsNullOrEmpty(Request.Email)
                    || Request.Avatar == null || Request.Avatar.Length == 0)
                {
                    return new ResponseObject<ResponseUser>
                    {
                        Status = StatusCodes.Status400BadRequest,
                        Message = "Vui lòng điền đầy đủ thông tin!",
                        Data = null
                    };
                }
                if (_Context.Users.Any(x => !Request.Username.ToLower().Equals(user.Username.ToLower()) && x.Username.ToLower().Equals(Request.Username.ToLower())))
                {
                    return new ResponseObject<ResponseUser>
                    {
                        Status = StatusCodes.Status400BadRequest,
                        Message = "Tài khoản đã tồn tại!",
                        Data = null
                    };
                }
                if (_Context.Users.Any(x => x.Email.ToLower().Equals(Request.Email.ToLower()) && !Request.Email.ToLower().Equals(user.Email.ToLower())))
                {
                    return new ResponseObject<ResponseUser>
                    {
                        Status = StatusCodes.Status400BadRequest,
                        Message = "Email đã tồn tại!",
                        Data = null
                    };
                }
                if (!ValidateEmail.IsEmail(Request.Email))
                {
                    return new ResponseObject<ResponseUser>
                    {
                        Status = StatusCodes.Status400BadRequest,
                        Message = "Eamil không đúng định dạng!",
                        Data = null
                    };
                }
                user.Username = Request.Username;
                user.Email = Request.Email;
                user.Password = BCryptNet.HashPassword(Request.Password);
                var avatarName = UploadImageAsync(Request.Avatar);
                user.Avatar = avatarName;
                user.FullName = Request.FullName;
                user.IsActive = Request.IsActive;
                user.IsLocked = Request.IsLocked;
                user.DateOfBirth = Request.DateOfBirth;
                user.UserStatusId = (int)Request.Status;
                _Context.SaveChanges();
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Cập nhật người dùng thành công!",
                    Data = _userConverter.EntityToDTO(user)
                };
            }
            return new ResponseObject<ResponseUser>
            {
                Status = StatusCodes.Status200OK,
                Message = "Bạn không đủ quyền hạn để sử dụng chức năng này!",
                Data = null
            };
        }
        //sửa thông tin của chính người dùng đang đăng nhập
        public ResponseObject<ResponseUser> UpdateUserForUserLogin(RequestUser Request)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa được xác thực!",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var IdUser = int.Parse(claim.Value);
            var user = _Context.Users.SingleOrDefault(x => x.Id == IdUser);
            if (!user.IsActive)
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (user.IsLocked)
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            if (string.IsNullOrEmpty(Request.Username)
                || string.IsNullOrEmpty(Request.Password)
                || string.IsNullOrEmpty(Request.FullName)
                || string.IsNullOrEmpty(Request.Email)
                || Request.Avatar == null || Request.Avatar.Length == 0)
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Vui lòng điền đầy đủ thông tin!",
                    Data = null
                };
            }
            if (_Context.Users.Any(x => !Request.Username.ToLower().Equals(user.Username.ToLower()) && x.Username.ToLower().Equals(Request.Username.ToLower())))
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Tài khoản đã tồn tại!",
                    Data = null
                };
            }
            if (_Context.Users.Any(x => x.Email.ToLower().Equals(Request.Email.ToLower()) && !Request.Email.ToLower().Equals(user.Email.ToLower())))
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Email đã tồn tại!",
                    Data = null
                };
            }
            if (!ValidateEmail.IsEmail(Request.Email))
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Eamil không đúng định dạng!",
                    Data = null
                };
            }
            user.Username = Request.Username;
            user.Email = Request.Email;
            user.Password = BCryptNet.HashPassword(Request.Password);
            var avatarName = UploadImageAsync(Request.Avatar);
            user.Avatar = avatarName;
            user.FullName = Request.FullName;
            user.IsActive = Request.IsActive;
            user.IsLocked = Request.IsLocked;
            user.DateOfBirth = Request.DateOfBirth;
            user.UserStatusId = (int)Request.Status;
            _Context.SaveChanges();
            return new ResponseObject<ResponseUser>
            {
                Status = StatusCodes.Status200OK,
                Message = "Cập nhật người dùng thành công!",
                Data = _userConverter.EntityToDTO(user)
            };
        }
        //Xóa người dùng (chỉ admin)
        public ResponseObject<IQueryable<ResponseUser>> DeleteUser(int id)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<IQueryable<ResponseUser>>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực!",
                    Data = null
                };
            }
            if (currentUser.IsInRole("Admin"))
            {
                var user = _Context.Users.Find(id);
                if (user != null)
                {
                    var collection = _Context.Collections.Where(x => x.UserId == id).AsQueryable();
                    //Xóa bộ sưu tập
                    _Context.RemoveRange(collection);
                    _Context.SaveChanges();
                    //Gỡ bài viết
                    var post = _Context.Posts.Where(x => x.UserId == id);
                    foreach (var item in post)
                    {
                        item.IsDeleted = true;
                        item.IsActive = false;
                        item.RemoveAt = DateTime.Now;
                    }
                    //xóa follow
                    var follow = _Context.RelationShips.Where(x => x.FollowerId == id || x.FollowingId == id).AsQueryable();

                    _Context.SaveChanges();
                    //xóa người dùng(Xóa vĩnh viễn khỏi database)
                    _Context.Users.Remove(user);
                    _Context.SaveChanges();
                    var listUser = _Context.Users.ToList().Select(x => _userConverter.EntityToDTO(x)).AsQueryable();
                    return new ResponseObject<IQueryable<ResponseUser>>
                    {
                        Status = StatusCodes.Status200OK,
                        Message = "Xóa người dùng thành công!",
                        Data = listUser
                    };
                }
                return new ResponseObject<IQueryable<ResponseUser>>
                {
                    Status = StatusCodes.Status404NotFound,
                    Message = "Người dùng không tồn tại!",
                    Data = null
                };
            }
            return new ResponseObject<IQueryable<ResponseUser>>
            {
                Status = StatusCodes.Status401Unauthorized,
                Message = "Bạn không đủ quyền hạn để dùng chức năng này!",
                Data = null
            };
        }
        //Khóa và mở khóa tài khoản 
        public ResponseObject<ResponseUser> LockOrUnlockAccount()
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực!",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var idUser = int.Parse(claim.Value);
            var user = _Context.Users.FirstOrDefault(x=>x.Id == idUser);
            if (user.IsLocked)
            {
                user.IsLocked = false;
                _Context.SaveChanges();
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Mở khóa tài khoản thành công!",
                    Data = _userConverter.EntityToDTO(user)
                };
            }
            else
            {

                user.IsLocked = true;
                _Context.SaveChanges();
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Khóa tài khoản thành công!",
                    Data = _userConverter.EntityToDTO(user)
                };
            }
        }
        //Ban tài khoản(Admin)
        public ResponseObject<ResponseUser> BanAccount(int iduser)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực!",
                    Data = null
                };
            }
            if(currentUser.IsInRole("Admin"))
            {
                var user = _Context.Users.FirstOrDefault(x => x.Id == iduser && x.IsActive);
                if (user == null)
                {
                    return new ResponseObject<ResponseUser>
                    {
                        Status = StatusCodes.Status400BadRequest,
                        Message = "Tài khoản này đã bị ban!",
                        Data = null
                    };
                }
                user.IsActive = false;
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Ban tài khoản thành công!",
                    Data = _userConverter.EntityToDTO(user)
                };
            }
            return new ResponseObject<ResponseUser>
            {
                Status = StatusCodes.Status200OK,
                Message = "Bạn không đủ quyền để thực hiện chức năng này!",
                Data = null
            };
        }
        //Set role for user (only Admin)
        public ResponseObject<ResponseUser> SetRoleForUser(int id, RoleType role)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực!",
                    Data = null
                };
            }
            if (currentUser.IsInRole("Admin"))
            {
                var user = _Context.Users.SingleOrDefault(x => x.Id == id);
                if (user == null)
                {
                    return new ResponseObject<ResponseUser>
                    {
                        Status = StatusCodes.Status404NotFound,
                        Message = "Người dùng không tồn tại!",
                        Data = null
                    };
                }
                if (!_Context.Roles.Any(x => x.Id == (int)role))
                {
                    return new ResponseObject<ResponseUser>
                    {
                        Status = StatusCodes.Status404NotFound,
                        Message = "Không tìm thấy role này!",
                        Data = null
                    };
                }
                user.RoleId = (int)role;
                _Context.SaveChanges();
                return new ResponseObject<ResponseUser>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Sửa role thành công!",
                    Data = _userConverter.EntityToDTO(user)
                };
            }
            return new ResponseObject<ResponseUser>
            {
                Status = StatusCodes.Status400BadRequest,
                Message = "Bạn không đủ quyền hạn để sử dụng chức năng này!",
                Data = null
            };
        }
        //User đang login đi follow user khác
        public ResponseObject<ResponseFollow> FollowingUser(int idUserWantFollow)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponseFollow>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var IDUser = int.Parse(claim.Value);
            var user = _Context.Users.FirstOrDefault(x => x.Id == IDUser);
            if (!user.IsActive)
            {
                return new ResponseObject<ResponseFollow>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (user.IsLocked)
            {
                return new ResponseObject<ResponseFollow>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            if (IDUser == idUserWantFollow)
            {
                return new ResponseObject<ResponseFollow>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Không thể folow chính mình!",
                    Data = null
                };
            }
            if (!_Context.Users.Any(x => x.Id == idUserWantFollow))
            {
                return new ResponseObject<ResponseFollow>
                {
                    Status = StatusCodes.Status404NotFound,
                    Message = "Không tìm thấy người dùng này!",
                    Data = null
                };
            }
            Relationship relationship = new Relationship
            {
                FollowerId = IDUser,
                FollowingId = idUserWantFollow
            };
            _Context.RelationShips.Add(relationship);
            _Context.SaveChanges();
            return new ResponseObject<ResponseFollow>
            {
                Status = StatusCodes.Status200OK,
                Message = "Folow thành công!",
                Data = _FlConverter.FollowToDTO(IDUser)
            };
        }
        //Xem số lượng người follow mình(User đang login)
        public ResponseObject<ResponseFollow> GetRelationShipOfUser()
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if(!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponseFollow>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var IDUser = int.Parse(claim.Value);
            var user = _Context.Users.FirstOrDefault(x => x.Id == IDUser);
            if (!user.IsActive)
            {
                return new ResponseObject<ResponseFollow>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (user.IsLocked)
            {
                return new ResponseObject<ResponseFollow>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            return new ResponseObject<ResponseFollow>
            {
                Status = StatusCodes.Status200OK,
                Message = "Thực hiện thao tác thành công",
                Data = _FlConverter.FollowToDTO(IDUser)
            };
        }
        //UnFollow người dùng
        public ResponseObject<ResponseFollow> UnFollow(int idUserWantUnFollow)
        {
            var currentUser = _contextAccessor.HttpContext.User;
            if (!currentUser.Identity.IsAuthenticated)
            {
                return new ResponseObject<ResponseFollow>
                {
                    Status = StatusCodes.Status400BadRequest,
                    Message = "Người dùng chưa xác thực",
                    Data = null
                };
            }
            var claim = currentUser.FindFirst("ID");
            var IDUser = int.Parse(claim.Value);
            var user = _Context.Users.FirstOrDefault(x => x.Id == IDUser);
            if (!user.IsActive)
            {
                return new ResponseObject<ResponseFollow>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị Ban!",
                    Data = null
                };
            }
            if (user.IsLocked)
            {
                return new ResponseObject<ResponseFollow>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Tài khoản của bạn đã bị khóa, vui lòng mở khóa để có thể sử dụng chức năng!",
                    Data = null
                };
            }
            if (_Context.Users.Any(y => y.Id == idUserWantUnFollow))
            {
                var relationship = _Context.RelationShips.FirstOrDefault(x=>x.FollowerId == IDUser && x.FollowingId == idUserWantUnFollow);
                if (relationship == null)
                {
                    return new ResponseObject<ResponseFollow>
                    {
                        Status = StatusCodes.Status404NotFound,
                        Message = "Bạn chưa follow người này",
                        Data = null
                    };
                }
                _Context.Remove(relationship);
                _Context.SaveChanges();
                return new ResponseObject<ResponseFollow>
                {
                    Status = StatusCodes.Status200OK,
                    Message = "Thực hiện thao tác thành công",
                    Data = _FlConverter.FollowToDTO(IDUser)
                };
            }
            return new ResponseObject<ResponseFollow>
            {
                Status = StatusCodes.Status404NotFound,
                Message = "Người dùng bạn muốn bỏ theo dõi không tồn tại",
                Data = null
            };
        }
        #endregion
    }
}
