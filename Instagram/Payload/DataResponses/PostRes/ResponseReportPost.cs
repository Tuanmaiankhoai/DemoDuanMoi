using Instagram.Enumerable;

namespace Instagram.Payload.DataResponses.PostRes
{
    public class ResponseReportPost
    {
        public int ReportId { get; set; }
        public int PostId { get; set; }
        public string TitlePost { get; set; }
        public string ReporterName { get; set; }
        public string ReportedUserName { get; set; }
        public ReportType ReportType { get; set; }
        public string ReportingReason { get; set; }
        public DateTime CreateAt { get; set; }
    }
}
