using Security.Models;

namespace Security.Repositories
{
    public interface IBookRepository
    {
        Task<Book> AddAsync(Book book);
        Task<IEnumerable<Book>> GetAllAsync();
        Task<Book?> GetByIdAsync(int id);
        Task UpdateAsync(Book book);
        Task DeleteAsync(Book book);
    }
}
