using System.Text.Json.Serialization;

namespace Instagram.Enumerable
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ReportType
    {
        Violence,                //Bạo lực - 0
        Harassment,              //Quấy rồi - 1
        InappropriateContent,    //Nội dung không phù hợp - 2
        Spam,                    //Spam - 3
        PrivacyViolation,        //Vi phạm quyền riêng tư - 4
        Misinformation,          //Thông tin sai lệch - 5
        CopyrightViolation,      //Vi phạm bản quyền - 6
        Other                    //Khác - 7
    }
}
