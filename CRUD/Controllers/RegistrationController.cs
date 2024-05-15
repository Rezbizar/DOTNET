using CRUD.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MySql.Data.MySqlClient;
using Microsoft.Extensions.Configuration;
using System.Data;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using System.Security.Cryptography;

namespace CRUD.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RegistrationController : ControllerBase
    {

        public RegistrationController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        //User registration 
        [HttpPost]
        [Route("registration")]
        public IActionResult Registration(Registration registration)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            string connectionString = _configuration.GetConnectionString("UserConnection");

            using (MySqlConnection con = new MySqlConnection(connectionString))
            {
                con.Open();

                // Check if user already exists
                MySqlCommand checkUserCmd = new MySqlCommand("SELECT COUNT(*) FROM Registration WHERE UserName = @UserName", con);
                checkUserCmd.Parameters.AddWithValue("@UserName", registration.UserName);

                int existingUserCount = Convert.ToInt32(checkUserCmd.ExecuteScalar());

                if (existingUserCount > 0)
                {
                    return Conflict("User already exists with this UserName");
                }

                // If user doesn't exist, proceed with registration
                MySqlCommand cmd = new MySqlCommand("INSERT INTO Registration(UserName,Password,Email,IsActive) VALUES(@UserName, @Password, @Email, @IsActive); SELECT LAST_INSERT_ID();", con);
                cmd.Parameters.AddWithValue("@UserName", registration.UserName);
                cmd.Parameters.AddWithValue("@Password", registration.Password);
                cmd.Parameters.AddWithValue("@Email", registration.Email);
                cmd.Parameters.AddWithValue("@IsActive", registration.IsActive);

                object result = cmd.ExecuteScalar();

                if (result != null && result != DBNull.Value)
                {
                    UInt64 userId = Convert.ToUInt64(result);

                    // Fetch registered user details
                    MySqlCommand fetchUserCmd = new MySqlCommand("SELECT * FROM Registration WHERE Id = @Id", con);
                    fetchUserCmd.Parameters.AddWithValue("@Id", userId);

                    using (MySqlDataReader reader = fetchUserCmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            var registeredUser = new
                            {
                                UserName = reader["UserName"].ToString(),
                                Email = reader["Email"].ToString(),
                                // Add other user details as needed
                            };

                            return Ok(registeredUser);
                        }
                    }

                    return BadRequest("Error retrieving registered user data");
                }
                else
                {
                    return BadRequest("Error registering user");
                }
            }
        }



        // Login method here...
        [HttpPost]
        [Route("login")]
        public IActionResult Login(LoginModel login)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            string connectionString = _configuration.GetConnectionString("UserConnection");

            using (MySqlConnection con = new MySqlConnection(connectionString))
            {
                MySqlCommand cmd = new MySqlCommand("SELECT * FROM Registration WHERE UserName = @UserName AND Password = @Password", con);
                cmd.Parameters.AddWithValue("@UserName", login.UserName);
                cmd.Parameters.AddWithValue("@Password", login.Password);

                con.Open();
                using (MySqlDataReader reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        //generate JWT token
                        var tokenHandler = new JwtSecurityTokenHandler();

                        // Generate a key with the required size
                        var key = new byte[32]; // 256 bits
                        using (var generator = RandomNumberGenerator.Create())
                        {
                            generator.GetBytes(key);
                        }

                        var tokenDescriptor = new SecurityTokenDescriptor
                        {
                            Subject = new ClaimsIdentity(new Claim[]
                            {
                            new Claim(ClaimTypes.Name, login.UserName),
                            new Claim("Password", login.Password)
                                    // Add more claims if needed
                                }),
                                Expires = DateTime.UtcNow.AddDays(30), // Token expires in 30 days
                                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(
                                Encoding.UTF8.GetBytes(configuration.GetConnectionString("JWT_Secret"))
                        ),
                        SecurityAlgorithms.HmacSha256Signature)
                        };
                        var token = tokenHandler.CreateToken(tokenDescriptor);
                        var tokenString = tokenHandler.WriteToken(token);

                        // Return the token along with user details
                        var userDetails = new
                        {
                            UserName = reader["UserName"].ToString(),
                            Email = reader["Email"].ToString(),
                            Token = tokenString  // Include the token in the response
                                                 // Add other user details as needed
                        };

                        return Ok(userDetails);
                    }
                }

                return Unauthorized("Invalid username or password");
            }
        }





        //Get all users
        [Authorize]
        [HttpGet]
        [Route("users")]
        public IActionResult GetAllUsers()
        {
            string connectionString = _configuration.GetConnectionString("UserConnection");

            List<object> allUsers = new List<object>();

            using (MySqlConnection con = new MySqlConnection(connectionString))
            {
                MySqlCommand cmd = new MySqlCommand("SELECT * FROM Registration", con);

                con.Open();
                using (MySqlDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var user = new
                        {
                            ID = reader["ID"].ToString(),
                            UserName = reader["UserName"].ToString(),
                            Email = reader["Email"].ToString(),
                            Password = reader["Password"].ToString(),
                            IsActive = reader["IsActive"].ToString()
                            // Add other user details as needed
                        };

                        allUsers.Add(user);
                    }
                }
            }

            return Ok(allUsers);
        }



        //Delete any user by id
        [HttpDelete]
        [Route("delete/{id}")]
        public IActionResult DeleteUser(int id)
        {
            string connectionString = _configuration.GetConnectionString("UserConnection");

            using (MySqlConnection con = new MySqlConnection(connectionString))
            {
                MySqlCommand cmd = new MySqlCommand("DELETE FROM Registration WHERE Id = @Id", con);
                cmd.Parameters.AddWithValue("@Id", id);

                con.Open();
                int rowsAffected = cmd.ExecuteNonQuery();

                if (rowsAffected > 0)
                {
                    return Ok($"User with ID {id} deleted successfully");
                }
                else
                {
                    return NotFound($"User with ID {id} not found");
                }
            }
        }


        //Edit user details by id
        [HttpPut]
        [Route("edit/{id}")]
        public IActionResult EditUser(int id, Registration updatedUser)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            string connectionString = _configuration.GetConnectionString("UserConnection");

            using (MySqlConnection con = new MySqlConnection(connectionString))
            {
                con.Open();

                // Check if user exists
                MySqlCommand checkUserCmd = new MySqlCommand("SELECT COUNT(*) FROM Registration WHERE Id = @Id", con);
                checkUserCmd.Parameters.AddWithValue("@Id", id);

                int existingUserCount = Convert.ToInt32(checkUserCmd.ExecuteScalar());

                if (existingUserCount == 0)
                {
                    return NotFound($"User with ID {id} not found");
                }

                // If user exists, proceed with updating details
                MySqlCommand cmd = new MySqlCommand("UPDATE Registration SET UserName = @UserName, Password = @Password, Email = @Email, IsActive = @IsActive WHERE Id = @Id", con);
                cmd.Parameters.AddWithValue("@Id", id);
                cmd.Parameters.AddWithValue("@UserName", updatedUser.UserName);
                cmd.Parameters.AddWithValue("@Password", updatedUser.Password);
                cmd.Parameters.AddWithValue("@Email", updatedUser.Email);
                cmd.Parameters.AddWithValue("@IsActive", updatedUser.IsActive);

                int rowsAffected = cmd.ExecuteNonQuery();

                if (rowsAffected > 0)
                {
                    return Ok($"User with ID {id} updated successfully");
                }
                else
                {
                    return BadRequest($"Error updating user with ID {id}");
                }
            }
        }




        //Add user by params data
        [HttpPost]
        [Route("addUserByParamsData")]
        public IActionResult AddUserByParamsData(string userName, string password, string email, int isActive)
        {
            if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(password) || string.IsNullOrEmpty(email))
            {
                return BadRequest("UserName, Password, and Email are required fields");
            }

            string connectionString = _configuration.GetConnectionString("UserConnection");

            using (MySqlConnection con = new MySqlConnection(connectionString))
            {
                con.Open();

                // Check if user already exists
                MySqlCommand checkUserCmd = new MySqlCommand("SELECT COUNT(*) FROM Registration WHERE UserName = @UserName", con);
                checkUserCmd.Parameters.AddWithValue("@UserName", userName);

                int existingUserCount = Convert.ToInt32(checkUserCmd.ExecuteScalar());

                if (existingUserCount > 0)
                {
                    return Conflict("User already exists with this UserName");
                }

                // If user doesn't exist, proceed with registration
                MySqlCommand cmd = new MySqlCommand("INSERT INTO Registration(UserName,Password,Email,IsActive) VALUES(@UserName, @Password, @Email, @IsActive)", con);
                cmd.Parameters.AddWithValue("@UserName", userName);
                cmd.Parameters.AddWithValue("@Password", password);
                cmd.Parameters.AddWithValue("@Email", email);
                cmd.Parameters.AddWithValue("@IsActive", isActive);

                int rowsAffected = cmd.ExecuteNonQuery();

                if (rowsAffected > 0)
                {
                    return Ok($"User {userName} added successfully");
                }
                else
                {
                    return BadRequest("Error adding user");
                }
            }
        }

    }
}
