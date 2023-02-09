using ApiDemo.Model.RSA;
using ApiDemo.Provider;
using System.Text;

namespace ApiDemo.Logic.RSA
{
    public class RSAService
    {
        private RSAProvider rsaProvider;
        public RSAService() 
        {
            InitializedRSAProvider(false, Encoding.UTF8); 
        }

        private void InitializedRSAProvider(bool isOAEP, Encoding coding)
        {
            rsaProvider = new RSAProvider(isOAEP, coding);
        }


        public async Task<KeyModel> RSAKeyGen()
        {            
            var res = new KeyModel
            {  
                PublicKey = rsaProvider.ExportPublicKey(),
                PrivateKey = rsaProvider.ExportPrivateKey(),
            };
            return res;
        }

        public async Task<RSAEncryptResponse> RSAEncrypt(RSAEncryptRequest model)
        { 
            var res = new RSAEncryptResponse();
            try
            {
                res.EncryptedText = rsaProvider.RsaEncryptWithPublic(model.Text, model.PublicKey);
            }
            catch (Exception ex)
            {
                res.EncryptedText = ex.Message;
            }
            return res;
        }

        internal async Task<RSADecryptResponse> RSADecrypt(RSADecryptRequest model)
        {
            var result = new RSADecryptResponse();
            try
            {
                result.DecryptedText = rsaProvider.RsaDecryptWithPrivate(model.Text, model.PrivateKey);
            }
            catch (Exception ex)
            {
                result.DecryptedText = ex.Message;
            }
            return result;
        }
    }
}
