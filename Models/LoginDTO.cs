using System.ComponentModel.DataAnnotations;

namespace LoginToDb.Models
{
    public class LoginDTO
    {
        [Required]
        public string Username { get; set; } =string.Empty;

        [Required]
        public string Passwordss { get; set; } = string.Empty;
    }
}
