using ApiDemo.Logic.RSA;
using ApiDemo.Model.RSA;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace ApiDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RsaController : ControllerBase
    {
        RSAService rSAService;
        public RsaController()
        {
            rSAService = new RSAService(); 

        }

        [HttpGet]
        [Route("KeyGen")]
        public async Task<KeyModel> KeyGen()
        {
            return await rSAService.RSAKeyGen();
        }

        [HttpPost]
        [Route("Encrypt")]
        public async Task<RSAEncryptResponse> Encrypt(RSAEncryptRequest model)
        {
            return await rSAService.RSAEncrypt(model);
        }

        [HttpPost]
        [Route("Decrypt")]
        public async Task<RSADecryptResponse> Decrypt(RSADecryptRequest model)
        {
            return await rSAService.RSADecrypt(model);
        }
    }
}
