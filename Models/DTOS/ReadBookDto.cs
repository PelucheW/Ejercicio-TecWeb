namespace Security.Models.DTOS
{
    public class ReadBookDto
    {
        public int Id { get; init; }
        public string Title { get; init; } = string.Empty;
        public string Author { get; init; } = string.Empty;
        public int Year { get; init; }
        public string? Genre { get; init; }
    }
}
