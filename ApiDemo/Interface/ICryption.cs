using System.Text;


namespace ApiDemo.Interface
{
    public interface ICryption
    {
        Encoding Encoding { get; set; }
        string Algorithm { get; }

        byte[] Hash { get; }

        string RsaEncryptWithPrivate(string clearText, string privateKey);

        string RsaEncryptWithPublic(string clearText, string publicKey);

        string RsaDecryptWithPrivate(string base64Input, string privateKey);

        string RsaDecryptWithPublic(string base64Input, string publicKey);

        string ExportPublicKey();

        string ExportPrivateKey();
    }
}
