namespace ApiDemo.Model.RSA
{
    public class RSAEncryptRequest
    {
        public string PublicKey { get; set; }
        public string Text { get; set; }
    }

    public class RSAEncryptResponse
    {
        public string EncryptedText { get; set; }
    }
}
