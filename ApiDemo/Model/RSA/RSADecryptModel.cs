namespace ApiDemo.Model.RSA
{
    public class RSADecryptRequest
    {
        public string PrivateKey { get; set; }
        public string Text { get; set; }
    }

    public class RSADecryptResponse
    {
        public string DecryptedText { get; set; }
    }
}
