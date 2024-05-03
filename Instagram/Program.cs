
using Instagram.Context;
using Instagram.Payload.Converters.CollectionConver;
using Instagram.Payload.Converters.FollowConvert;
using Instagram.Payload.Converters.PostConvert;
using Instagram.Payload.Converters.UserConvert;
using Instagram.Services.Impelment;
using Instagram.Services.Interface;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

namespace Instagram
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddDbContext<AppDbContext>(option => option.UseSqlServer(builder.Configuration.GetConnectionString("ConnectionDefault")));
            #region Add Scoped
            builder.Services.AddScoped<IUserService, UserService>();
            builder.Services.AddScoped<IPostService, PostService>();
            builder.Services.AddScoped<ICollectionService, CollectionService>();
            builder.Services.AddScoped<IOtherUserImpactPostService, OtherUserImpactPostService>();
            builder.Services.AddScoped<CollectionConverter>();
            builder.Services.AddScoped<ComentConverter>();
            builder.Services.AddScoped<ReportConverter>();
            builder.Services.AddScoped<PostCollectionConverter>();
            builder.Services.AddScoped<PostConverter>();
            builder.Services.AddScoped<UserConverter>();
            builder.Services.AddScoped<FollowConverter>();
            #endregion
            builder.Services.AddHttpContextAccessor();
            builder.Services.AddSwaggerGen();
            // builder.Services.AddScoped<IConfiguration>();
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(x => 
            {
                x.RequireHttpsMetadata = false;
                x.SaveToken = true;
                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration.GetSection("AppSettings:SecretKey").Value))
                };
            });
            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
