using Security.Models;
using Security.Models.DTOS;
using Security.Repositories;
namespace Security.Services
{
    public class BookService : IBookService
    {
        private readonly IBookRepository _repo;
        public BookService(IBookRepository repo) => _repo = repo;

        public async Task<Book> CreateAsync(CreateBookDto dto)
        {
            var book = new Book
            {
                Title = dto.Title.Trim(),
                Author = dto.Author.Trim(),
                Year = dto.Year,
                Genre = dto.Genre?.Trim()
            };
            return await _repo.AddAsync(book);
        }

        public async Task<IEnumerable<Book>> GetAllAsync() => await _repo.GetAllAsync();

        public async Task<Book?> GetByIdAsync(int id) => await _repo.GetByIdAsync(id);

        public async Task<Book?> UpdateAsync(int id, UpdateBookDto dto)
        {
            var existing = await _repo.GetByIdAsync(id);
            if (existing == null) return null;
            existing.Title = dto.Title.Trim();
            existing.Author = dto.Author.Trim();
            existing.Year = dto.Year;
            existing.Genre = dto.Genre?.Trim();
            await _repo.UpdateAsync(existing);
            return existing;
        }

        public async Task<bool> DeleteAsync(int id)
        {
            var existing = await _repo.GetByIdAsync(id);
            if (existing == null) return false;
            await _repo.DeleteAsync(existing);
            return true;
        }
    }
}
