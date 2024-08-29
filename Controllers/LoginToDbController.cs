using LoginToDb.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace LoginToDb.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginToDbController : ControllerBase
    {
        public readonly string connectionString;
        public static Login user = new Login();
        public static LoginDTO loginDto = new LoginDTO();
        private readonly IConfiguration configurations;

        public LoginToDbController(IConfiguration configuration)
        {
            connectionString = configuration["ConnectionStrings:ConnectDb"] ?? "";
            this.configurations = configurations;
        }
        [HttpPost("(Register)")]
        public async Task<ActionResult<Login>> Register(LoginDTO request)
        {
            CreatePasswordHash(request.Passwordss, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            try
                {
                    using (SqlConnection connection = new SqlConnection(connectionString))
                    {
                        connection.Open();

                        string sql = "INSERT INTO UserData " +
                            "(Username, Passwordss) VALUES " +
                            "(@Username, @Passwordss)";

                        using (var command = new SqlCommand(sql, connection))
                        {
                            command.Parameters.AddWithValue("@Username", request.Username);
                            command.Parameters.AddWithValue("@Passwordss",passwordHash);

                            command.ExecuteNonQuery();
                        }
                    }
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("Login", "Sorry we caught an error");
                    return BadRequest(ModelState);
                }
            //return Ok(await configurations.Login.ToListAsync());
            return Ok(user);
        }
        private void CreatePasswordHash(string passwordss, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(passwordss));
            }
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(LoginDTO request)
        {
            if (user.Username != request.Username)
            {

                return BadRequest("User not found");
            }
            if (!VerifyPasswordHash(request.Passwordss, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong Password.");
            }

            string token = CreateToken(user);

            return Ok(token);
        }
        private string CreateToken(Login user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF32.GetBytes(
                configurations.GetSection("AppSettings:Token").Value));


            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
        private bool VerifyPasswordHash(string passwordss, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(passwordss));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

            [HttpGet]
            public IActionResult GetUsers()
            {
                List<Login> login = new List<Login>();

                try
                {
                    using (var connection = new SqlConnection(connectionString))
                    {
                        connection.Open();

                        string sql = "SELECT * FROM UserData ";

                        using (var command = new SqlCommand(sql, connection))
                        {
                            using (var reader = command.ExecuteReader())
                            {
                                while (reader.Read())
                                {
                                    Login logins = new Login();

                                    logins.Id = reader.GetInt32(0);
                                    logins.Username = reader.GetString(1);
                                    logins.Created_at = reader.GetDateTime(2);

                                    login.Add(logins);
                                }
                            }
                        }
                    }
                }

                catch (Exception ex)
                {
                    ModelState.AddModelError("Login", "Sorry we caught an error");
                    return BadRequest(ModelState);
                }
                return Ok(login);
            }

        [HttpDelete("(id)")]
        public IActionResult DeleteProduct(int id)
        {
            try
            {
                using (var connection = new SqlConnection(connectionString))
                {
                    connection.Open();

                    string sql = "DELETE FROM UserData WHERE id=@id";

                    using (var command = new SqlCommand(sql, connection))
                    {
                        command.Parameters.AddWithValue("@id", id);

                        command.ExecuteNonQuery();
                    }
                }
            }

            catch (Exception ex)
            {
                ModelState.AddModelError("Login", "Sorry we caught an error");
                return BadRequest(ModelState);
            }

            return Ok();
        }
    }
}
