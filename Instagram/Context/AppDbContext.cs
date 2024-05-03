using Instagram.Entities;
using Microsoft.EntityFrameworkCore;

namespace Instagram.Context
{
    public class AppDbContext:DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<Collection> Collections { get; set; }
        public DbSet<ConfirmEmail> ConfirmEmails { get; set; }
        public DbSet<PostCollection> PostCollections { get; set; }
        public DbSet<Post> Posts { get; set; }
        public DbSet<PostStatus> PostStatus { get; set; }
        public DbSet<RefeshToken> RefreshTokens { get; set; }
        public DbSet<Relationship> RelationShips { get; set; }
        public DbSet<Report> Reports { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<UserCommentPost> userCommentPosts { get; set; }
        public DbSet<UserLikeCommentPost> UserLikesComments { get; set; }
        public DbSet<UserLikePost> UserLikePosts { get; set; }
        public DbSet<User> Users { get; set; }
        public DbSet<UserStatus> UserStatus { get; set; }
        //protected override void OnModelCreating(ModelBuilder modelBuilder)
        //{
        //    base.OnModelCreating(modelBuilder);

        //    if (modelBuilder.Model != null)
        //    {
        //        foreach (var relationship in modelBuilder.Model.GetEntityTypes().SelectMany(e => e.GetForeignKeys()))
        //        {
        //            relationship.DeleteBehavior = DeleteBehavior.NoAction;
        //        }
        //    }
        //}
    }
}
