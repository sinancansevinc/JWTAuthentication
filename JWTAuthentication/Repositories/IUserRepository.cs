using JWTAuthentication.Dto;

namespace JWTAuthentication.Repositories
{
	public interface IUserRepository
	{
		string GetToken(string username, List<string> roles);
		bool IsUniqueUser(string username);
		Task<LoginResponseDTO> Login(LoginRequestDTO loginRequestDTO);
		Task<UserDTO> Register(RegistrationRequestDTO registrationRequestDTO);
	}
}