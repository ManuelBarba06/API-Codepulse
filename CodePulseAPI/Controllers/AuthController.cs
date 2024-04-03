using CodePulseAPI.Models.DTO;
using CodePulseAPI.Repositories.Interface;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CodePulseAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly ITokenRepository tokenRepository;

        public AuthController(UserManager<IdentityUser> userManager,
            ITokenRepository tokenRepository)
        {
            this.userManager = userManager;
            this.tokenRepository = tokenRepository;
        }

        //POST: /api/auth/login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
        {
           var identifyUser = await userManager.FindByEmailAsync(request.Email);

           if (identifyUser is not null)
            {
                var checkPasswordResult = await userManager.CheckPasswordAsync(identifyUser, request.Password);

                if (checkPasswordResult)
                {
                    var roles = await userManager.GetRolesAsync(identifyUser);

                    var jwtToken = tokenRepository.CreateJwtToken(identifyUser, roles.ToList());

                    var response = new LoginResponseDto()
                    {
                        Email = request.Email,
                        Roles = roles.ToList(),
                        Token = jwtToken

                    };

                    return Ok(response);
                }
            }

            ModelState.AddModelError("", "Email or Password Inccorrect");

            return ValidationProblem(ModelState);
        }

        //POST: /api/auth/register
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDto request)
        {
            var user = new IdentityUser
            {
                UserName = request.Email?.Trim(),
                Email = request.Email?.Trim(),
            };

           var identityResult = await userManager.CreateAsync(user, request.Password);

           if (identityResult.Succeeded)
            {
                // Add Role to user (Reader)
                identityResult = await userManager.AddToRoleAsync(user, "Reader");

                if (identityResult.Succeeded)
                {
                    return Ok();
                }
                else
                {
                    if (identityResult.Errors.Any())
                    {
                        foreach (var error in identityResult.Errors)
                        {
                            ModelState.AddModelError("", error.Description);
                        }
                    }
                }

            } else
            {
                if (identityResult.Errors.Any())
                {
                    foreach (var error in identityResult.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }
            }

            return ValidationProblem(ModelState);
        }
    }
}
