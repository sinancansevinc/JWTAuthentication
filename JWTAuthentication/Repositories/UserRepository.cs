using JWTAuthentication.Data;
using JWTAuthentication.Dto;
using JWTAuthentication.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthentication.Repositories
{
	public class UserRepository : IUserRepository
	{
		private string secretKey;
		private readonly ApplicationDbContext _context;
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly RoleManager<IdentityRole> _roleManager;

		public UserRepository(IConfiguration _configuration, ApplicationDbContext context, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
		{
			secretKey = _configuration.GetSection("JWTParameters:SecretKey").Value;
			_context = context;
			_userManager = userManager;
			_roleManager = roleManager;
		}

		public bool IsUniqueUser(string username)
		{
			var user = _context.ApplicationUsers.FirstOrDefault(p => p.UserName.ToLower() == username.ToLower());
			if (user != null)
			{
				return false;
			}

			return true;

		}

		public async Task<LoginResponseDTO> Login(LoginRequestDTO loginRequestDTO)
		{
			var user = await _context.ApplicationUsers.FirstOrDefaultAsync(p => p.UserName.ToLower() == loginRequestDTO.UserName.ToLower());
			bool isValid = await _userManager.CheckPasswordAsync(user, loginRequestDTO.Password);
			if (user == null || !isValid)
			{
				return new LoginResponseDTO()
				{
					Token = "",
					User = null
				};
			}

			var roles = await _userManager.GetRolesAsync(user);
			var token = GetToken(user.UserName, roles.ToList());

			return new LoginResponseDTO()
			{
				Token = token,
				User = new UserDTO()
				{
					Id = user.Id,
					Name = user.Name,
					UserName = user.UserName
				}
			};
		}

		public async Task<UserDTO> Register(RegistrationRequestDTO registrationRequestDTO)
		{
			ApplicationUser user = new()
			{
				UserName = registrationRequestDTO.UserName,
				Email = registrationRequestDTO.UserName,
				Name = registrationRequestDTO.Name,
				NormalizedEmail = registrationRequestDTO.UserName.ToUpper()
			};

			try
			{
				var result = await _userManager.CreateAsync(user, registrationRequestDTO.Password);
				if (result.Succeeded)
				{
					if (!_roleManager.RoleExistsAsync("admin").GetAwaiter().GetResult())
					{
						await _roleManager.CreateAsync(new IdentityRole("admin"));
						await _roleManager.CreateAsync(new IdentityRole("customer"));
					}

					await _userManager.AddToRoleAsync(user, "admin");
					return new UserDTO()
					{
						Id = user.Id,
						Name = user.Name,
						UserName = user.UserName
					};
				}
			}
			catch (Exception)
			{

				throw;
			}

			return new UserDTO();

		}

		public string GetToken(string username, List<string> roles)
		{
			var key = Encoding.ASCII.GetBytes(secretKey);
			var tokenHandler = new JwtSecurityTokenHandler();

			var tokenDescriptor = new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(new Claim[]
				{
					new Claim(ClaimTypes.Name,username),
					new Claim(ClaimTypes.Role,roles.FirstOrDefault())
				}),
				Expires = DateTime.UtcNow.AddDays(1),
				SigningCredentials = new(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
			};

			var token = tokenHandler.CreateToken(tokenDescriptor);
			return tokenHandler.WriteToken(token);
		}
	}
}
