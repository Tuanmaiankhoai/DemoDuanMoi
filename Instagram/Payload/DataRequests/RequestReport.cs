using Instagram.Entities;
using Instagram.Enumerable;
using System.ComponentModel.DataAnnotations.Schema;

namespace Instagram.Payload.DataRequests
{
    public class RequestReport
    {
        public int PostId { get; set; }
        public ReportType ReportType { get; set; } //Kiểu báo cáo
        public string ReportingReason { get; set; } //Lý do báo cáo
    }
}
