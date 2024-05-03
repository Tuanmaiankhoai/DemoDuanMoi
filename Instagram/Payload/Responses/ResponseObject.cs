namespace Instagram.Payload.Responses
{
    public class ResponseObject<T>
    {
        public int Status { get; set; }
        public string Message { get; set; }
        public T Data { get; set; }
        public ResponseObject() { }
        public ResponseObject(int status, string message, T value)
        {
            Status = status;
            Message = message;
            Data = value;
        }
        public ResponseObject<T> ResponseSuccess(string msg, T data) 
        {
            return new ResponseObject<T>(StatusCodes.Status200OK, msg, data); 
        }
        public ResponseObject<T> ResponseError(int status, string msg, T data)
        {
            return new ResponseObject<T>(status, msg, data);
        }
    }
}
