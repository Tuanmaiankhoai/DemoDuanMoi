using System.Text.Json.Serialization;

namespace Instagram.Enumerable
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum TypeOfPostStatus
    {
        //dữ liệu được lấy từ bảng PostStatus trong db
        OnlyMe = 1, //Chỉ mình tôi
        Public = 2, //Công khai
        Friend = 3  //Chỉ bạn bè
    }
}
