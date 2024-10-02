using AutoMapper;
using JwtAuthentication.Authentication;
using JwtAuthentication.Dto;
using JwtAuthentication.Models.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController(UserManager<User> _userManager,SignInManager<User> _signInManager,IMapper _mapper, AuthenticationServices _authenticationServices) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<IdentityResult> RegisterUser([FromBody]UserForRegistrationDto model)
        {
            var user = _mapper.Map<User>(model);

            var result = await _userManager.CreateAsync(user,model.Password);

            //Role tanimlama
            if (result.Succeeded)
            {
                //birden fazla role tanimimiz vardi UserForRegistrationDto gidip bakabilrisin collection icinde
                await _userManager.AddToRolesAsync(user, model.Roles);
            }

            return result;

        }

        [HttpPost("login")]
        public async Task<IActionResult> Authenticate([FromBody] UserForAuthenticationDto user)
        {
            if (!await _authenticationServices.ValidateUser(user))
                return Unauthorized(); //401

            var tokenDto = await _authenticationServices.CreateToken(populateExp: true);

            return Ok(tokenDto);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody]TokenDto tokenDto)
        {
            var tokenDtoToReturn = await _authenticationServices.RefreshToken(tokenDto);

            return Ok(tokenDtoToReturn);
        }



        [Authorize(Roles = "User")]
        [HttpGet("USERGET1")]
        public IActionResult Get1()
        {
            var strg = "useree!!";
            return Ok(strg);
        }

        [Authorize(Roles ="Editor")]
        [HttpGet("EDITORGET2")]
        public IActionResult Get2()
        {
            var strg = "editor!!";
            return Ok(strg);
        }

        [Authorize(Roles ="Admin")]
        [HttpGet("ADMINGET3")]
        public IActionResult Get3()
        {
            var strg = "adminnn!!";
            return Ok(strg);
        }


    }
}
