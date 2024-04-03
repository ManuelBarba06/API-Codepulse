using CodePulseAPI.Data;
using CodePulseAPI.Models.Domain;
using CodePulseAPI.Repositories.Interface;
using Microsoft.EntityFrameworkCore;

namespace CodePulseAPI.Repositories.Implementation
{
    public class BlogPostRepository : IBlogPostRepository
    {
        public ApplicationDbContext dbContext { get; }

        public BlogPostRepository(ApplicationDbContext dbContext)
        {
            this.dbContext = dbContext;
        }


        public async Task<BlogPost> CreateAsync(BlogPost blogPost)
        {
            await dbContext.BlogPost.AddAsync(blogPost);
            await dbContext.SaveChangesAsync();
            return blogPost;
        }

        public async Task<IEnumerable<BlogPost>> GetAllAsync()
        {
            return await dbContext.BlogPost.Include(x => x.Categories).ToListAsync();
        }

        public async Task<BlogPost?> GetByIdAsync(Guid id)
        {
            return await dbContext.BlogPost.Include(x => x.Categories).FirstOrDefaultAsync(x => x.Id == id);
        }

        public async Task<BlogPost?> UpdateAsync(BlogPost blogPost)
        {
            var existingBlogPost = await dbContext.BlogPost.Include(x => x.Categories)
                    .FirstOrDefaultAsync(x => x.Id == blogPost.Id);

            if (existingBlogPost == null)
            {
                return null;
            }

            dbContext.Entry(existingBlogPost).CurrentValues.SetValues(blogPost);

            existingBlogPost.Categories = blogPost.Categories;

            await dbContext.SaveChangesAsync();

            return blogPost;
        }

        public async Task<BlogPost?> DeleteAsync(Guid id)
        {
            var existingBlogPost = await dbContext.BlogPost.FirstOrDefaultAsync(x => x.Id == id);
            
            if (existingBlogPost != null)
            {
                dbContext.BlogPost.Remove(existingBlogPost);
                await dbContext.SaveChangesAsync();
                return existingBlogPost;
            }

            return null;
        }

        public async Task<BlogPost?> GetByUrlHandleAsync(string urlHandle)
        {
            return await dbContext.BlogPost.Include(x => x.Categories).FirstOrDefaultAsync(x => x.UrlHandle == urlHandle);
        }
    }
}
