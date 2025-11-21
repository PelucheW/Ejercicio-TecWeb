using System.ComponentModel.DataAnnotations;

namespace Security.Models
{
    public class Book
    {
        public int Id { get; set; }

        [Required, StringLength(200)]
        public string Title { get; set; } = string.Empty;

        [Required, StringLength(150)]
        public string Author { get; set; } = string.Empty;

        public int Year { get; set; }

        [StringLength(100)]
        public string? Genre { get; set; }
    }
}
