using Newtonsoft.Json;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Pkcs;
using System.Xml.Serialization;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using ApiDemo.Interface;

namespace ApiDemo.Provider
{
    public class RSAProvider : ICryption, IDisposable
    {
        private RsaKeyPairGenerator keyGen = new RsaKeyPairGenerator();
        private string publicKey = string.Empty;
        private string privateKey = string.Empty;
        private bool disposedValue;
        private int keyLength = 2048;

        /// <summary>
        /// 建立RSA服務
        /// </summary>
        /// <param name="publicKey">公鑰</param>
        /// <param name="privateKey">私鑰</param>
        public RSAProvider(bool IsFOAEP, Encoding encoding)
        {
            GenerateRSAInstance();
            Encoding = encoding;
            this.IsFOAEP = IsFOAEP;
        }

        private void GenerateRSAInstance()
        {
            RsaKeyGenerationParameters param = new RsaKeyGenerationParameters(
               Org.BouncyCastle.Math.BigInteger.ValueOf(3),
               new SecureRandom(), keyLength, 25);
            keyGen.Init(param);
            AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();
            AsymmetricKeyParameter publicKey = keyPair.Public;
            AsymmetricKeyParameter privateKey = keyPair.Private;

            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);

            Asn1Object asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();

            byte[] publicInfoByte = asn1ObjectPublic.GetEncoded("UTF-8");
            Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
            byte[] privateInfoByte = asn1ObjectPrivate.GetEncoded("UTF-8");

            this.publicKey = Convert.ToBase64String(publicInfoByte);
            this.privateKey = Convert.ToBase64String(privateInfoByte);
        }

        string ICryption.Algorithm => "RSA";

        byte[] ICryption.Hash => throw new NotImplementedException();

        public Encoding Encoding { get; set; }

        public bool IsFOAEP { get; set; }

        public string ExportPublicKey()
        {
            return this.publicKey;
        }

        public string ExportPrivateKey()
        {
            return this.privateKey;
        }

        public string RsaEncryptWithPublic(string clearText, string publicKey)
        {
            publicKey = PublicToPemFormat(publicKey);
            var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);

            var encryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(publicKey))
            {
                var keyParameter = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();

                encryptEngine.Init(true, keyParameter);
            }

            var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
            return encrypted;

        }

        public string RsaEncryptWithPrivate(string clearText, string privateKey)
        {
            privateKey = PrivateToPemFormat(privateKey);
            var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);

            var encryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(privateKey))
            {
                var keyPair = (RsaPrivateCrtKeyParameters)new PemReader(txtreader).ReadObject();

                encryptEngine.Init(true, keyPair);
            }

            var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
            return encrypted;
        }


        // Decryption:

        public string RsaDecryptWithPrivate(string base64Input, string privateKey)
        {
            privateKey = PrivateToPemFormat(privateKey);
            var bytesToDecrypt = Convert.FromBase64String(base64Input);

            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(privateKey))
            {
                var keyPair = (RsaPrivateCrtKeyParameters)new PemReader(txtreader).ReadObject();

                decryptEngine.Init(false, keyPair);
            }

            var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
            return decrypted;
        }

        public string RsaDecryptWithPublic(string base64Input, string publicKey)
        {
            publicKey = PublicToPemFormat(publicKey);
            var bytesToDecrypt = Convert.FromBase64String(base64Input);

            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var txtreader = new StringReader(publicKey))
            {
                var keyParameter = (AsymmetricKeyParameter)new PemReader(txtreader).ReadObject();

                decryptEngine.Init(false, keyParameter);
            }

            var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
            return decrypted;
        }

        private string PrivateToPemFormat(string privateKey)
        {
            var result = $"-----BEGIN PRIVATE KEY----- {privateKey} -----END PRIVATE KEY-----";
            return result;
        }

        private string PublicToPemFormat(string publicKey)
        {
            var result = $"-----BEGIN PUBLIC KEY----- {publicKey} -----END PUBLIC KEY-----";
            return result;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: 處置受控狀態 (受控物件)
                }

                // TODO: 釋出非受控資源 (非受控物件) 並覆寫完成項
                // TODO: 將大型欄位設為 Null
                disposedValue = true;
            }
        }

        // // TODO: 僅有當 'Dispose(bool disposing)' 具有會釋出非受控資源的程式碼時，才覆寫完成項
        // ~RSAProvider()
        // {
        //     // 請勿變更此程式碼。請將清除程式碼放入 'Dispose(bool disposing)' 方法
        //     Dispose(disposing: false);
        // }

        public void Dispose()
        {
            // 請勿變更此程式碼。請將清除程式碼放入 'Dispose(bool disposing)' 方法
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
