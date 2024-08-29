namespace LoginToDb.Models
{
    public class Login
    {
        public int Id { get; set; }

        public string Username { get; set; } = "";

        public byte[] PasswordHash { get; set; }

        public byte[] PasswordSalt { get; set; }

        public DateTime Created_at { get; set; }
    }
}
