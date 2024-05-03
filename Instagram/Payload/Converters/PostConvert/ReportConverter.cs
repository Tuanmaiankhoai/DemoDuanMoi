using Instagram.Context;
using Instagram.Entities;
using Instagram.Payload.DataResponses.PostRes;

namespace Instagram.Payload.Converters.PostConvert
{
    public class ReportConverter
    {
        private readonly AppDbContext _context;
        public ReportConverter(AppDbContext context)
        {
            _context = context;
        }
        public ResponseReportPost ReportToDTO(Report report)
        {
            return new ResponseReportPost
            {
                ReportId = report.Id,
                PostId = report.PostId,
                TitlePost = _context.Posts.SingleOrDefault(x=>x.Id == report.PostId).Title,
                ReporterName = _context.Users.SingleOrDefault(y=>y.Id == report.UserReporterId).FullName,
                ReportedUserName = _context.Users.SingleOrDefault(c => c.Id == report.UserReportId).FullName,
                ReportType = report.ReportType,
                ReportingReason = report.ReportingReason,
                CreateAt = report.CreateAt
            };
        }
    }
}
