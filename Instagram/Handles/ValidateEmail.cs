using System.ComponentModel.DataAnnotations;

namespace Instagram.Validates
{
    public class ValidateEmail
    {
        public static bool IsEmail(string email)
        {
            var checkEmail = new EmailAddressAttribute();
            return checkEmail.IsValid(email);
        }
    }
}
