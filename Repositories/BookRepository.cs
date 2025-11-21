using Microsoft.EntityFrameworkCore;
using Security.Data;
using Security.Models;


namespace Security.Repositories
{
    public class BookRepository : IBookRepository
    {
        private readonly AppDbContext _ctx;
        public BookRepository(AppDbContext ctx) => _ctx = ctx;

        public async Task<Book> AddAsync(Book book)
        {
            await _ctx.Books.AddAsync(book);
            await _ctx.SaveChangesAsync();
            return book;
        }

        public Task<IEnumerable<Book>> GetAllAsync() =>
            Task.FromResult<IEnumerable<Book>>(_ctx.Books.AsNoTracking().ToList());

        public Task<Book?> GetByIdAsync(int id) =>
            _ctx.Books.AsNoTracking().FirstOrDefaultAsync(b => b.Id == id);

        public async Task UpdateAsync(Book book)
        {
            _ctx.Books.Update(book);
            await _ctx.SaveChangesAsync();
        }

        public async Task DeleteAsync(Book book)
        {
            _ctx.Books.Remove(book);
            await _ctx.SaveChangesAsync();
        }
    }
}
