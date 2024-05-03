using Instagram.Enumerable;
using System.ComponentModel.DataAnnotations.Schema;

namespace Instagram.Entities
{
    public class Report:Base
    {
        public int PostId { get; set; }
        public Post? Post { get; set; }
        [ForeignKey("UserReport")]
        public int UserReportId { get; set; }
        public User? UserReport{ get; set; }
        public ReportType ReportType { get; set; }
        [ForeignKey("UserReporter")]
        public int UserReporterId { get; set; }
        public User? UserReporter { get; set; }
        public string ReportingReason { get; set; }
        public DateTime CreateAt { get; set; }
    }
}
