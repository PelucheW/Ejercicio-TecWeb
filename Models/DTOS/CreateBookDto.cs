using System.ComponentModel.DataAnnotations;

namespace Security.Models.DTOS
{
    public class CreateBookDto
    {
        [Required, StringLength(200)]
        public string Title { get; init; } = string.Empty;

        [Required, StringLength(150)]
        public string Author { get; init; } = string.Empty;

        public int Year { get; init; }

        public string? Genre { get; init; }
    }
}
