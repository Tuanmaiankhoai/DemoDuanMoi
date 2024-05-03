using System.Text.Json.Serialization;

namespace Instagram.Enumerable
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum RoleType
    {
        //dữ liệu được lấy từ bảng Role trong database
        User = 1,
        Admin = 2,
    }
}
