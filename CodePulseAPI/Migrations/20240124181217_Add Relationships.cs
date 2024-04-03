using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CodePulseAPI.Migrations
{
    /// <inheritdoc />
    public partial class AddRelationships : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropPrimaryKey(
                name: "PK_categories",
                table: "categories");

            migrationBuilder.RenameTable(
                name: "categories",
                newName: "Categories");

            migrationBuilder.AddPrimaryKey(
                name: "PK_Categories",
                table: "Categories",
                column: "Id");

            migrationBuilder.CreateTable(
                name: "BlogPostCategory",
                columns: table => new
                {
                    BlogPostsId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CategoriesId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BlogPostCategory", x => new { x.BlogPostsId, x.CategoriesId });
                    table.ForeignKey(
                        name: "FK_BlogPostCategory_BlogPost_BlogPostsId",
                        column: x => x.BlogPostsId,
                        principalTable: "BlogPost",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_BlogPostCategory_Categories_CategoriesId",
                        column: x => x.CategoriesId,
                        principalTable: "Categories",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_BlogPostCategory_CategoriesId",
                table: "BlogPostCategory",
                column: "CategoriesId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "BlogPostCategory");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Categories",
                table: "Categories");

            migrationBuilder.RenameTable(
                name: "Categories",
                newName: "categories");

            migrationBuilder.AddPrimaryKey(
                name: "PK_categories",
                table: "categories",
                column: "Id");
        }
    }
}
