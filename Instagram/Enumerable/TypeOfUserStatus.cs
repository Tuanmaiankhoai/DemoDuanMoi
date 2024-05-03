using System.Text.Json.Serialization;

namespace Instagram.Enumerable
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum TypeOfUserStatus
    {
        //dữ liệu được lấy từ bảng UserStatus trong database
        Online = 1,
        Offline = 2
    }
}
