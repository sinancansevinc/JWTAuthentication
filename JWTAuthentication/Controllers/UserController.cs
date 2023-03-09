using JWTAuthentication.Dto;
using JWTAuthentication.Repositories;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthentication.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class UserController : ControllerBase
	{
		private readonly IUserRepository _userRepository;

		public UserController(IUserRepository userRepository)
		{
			_userRepository = userRepository;
		}
		
		[HttpPost("register")]
		public async Task<IActionResult> Register([FromBody] RegistrationRequestDTO registrationRequestDTO)
		{
			bool isUserNameUnique = _userRepository.IsUniqueUser(registrationRequestDTO.UserName);
			if (!isUserNameUnique)
			{
				return BadRequest("Username is exist");
			}

			var registerResponse = await _userRepository.Register(registrationRequestDTO);
			if (registerResponse == null)
			{
				return BadRequest("There is an error while registration");
			}

			return Ok(registerResponse);

		}

		[HttpPost("login")]
		public async Task<IActionResult> Login([FromBody] LoginRequestDTO loginRequestDTO)
		{
			var loginResponse = await _userRepository.Login(loginRequestDTO);
			if (loginResponse.User == null || string.IsNullOrEmpty(loginResponse.Token))
			{
				return BadRequest("Username or password is incorrect");
			}

			return Ok(loginResponse);
		}



	}
}
