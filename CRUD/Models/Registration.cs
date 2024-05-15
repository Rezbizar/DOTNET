using System.ComponentModel.DataAnnotations;

namespace CRUD.Models
{
    public class Registration
    {
        public int ID { get; set; }

        [Required(ErrorMessage = "Username is required")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; }

        [Required(ErrorMessage = "IsActive is required")]
        public int IsActive { get; set; }
    }
}
