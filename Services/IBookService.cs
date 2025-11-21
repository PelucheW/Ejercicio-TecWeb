using Security.Models;
using Security.Models.DTOS;

namespace Security.Services
{
    public interface IBookService
    {
        Task<Book> CreateAsync(CreateBookDto dto);
        Task<IEnumerable<Book>> GetAllAsync();
        Task<Book?> GetByIdAsync(int id);
        Task<Book?> UpdateAsync(int id, UpdateBookDto dto);
        Task<bool> DeleteAsync(int id);
    }
}
