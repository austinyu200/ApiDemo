using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ApiDemo.Provider
{
    public class AESProvider
    {
        private string iv = string.Empty;
        private string key = string.Empty;
        private PaddingMode paddingMode;
        private CipherMode cipherMode;
        private Aes aes;
        private Encoding encoding;
        private string encryptInput, encryptOutput;
        private string decryptInput, decryptOutput;

        public AESProvider()
        {
            encoding = encoding ?? Encoding.UTF8;
            aes = Aes.Create();
            aes.KeySize = 256;
            aes.GenerateIV();
            aes.GenerateKey();
            key = encoding.GetString(aes.Key);
            iv = encoding.GetString(aes.IV);
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
        }

        public AESProvider(string iv, string key, CipherMode mode, PaddingMode padding, Encoding encoding)
        {
            this.encoding = encoding;
            Validate_KeyIV_Length(key, iv);
            aes = Aes.Create();
            aes.IV = encoding.GetBytes(iv);
            aes.Key = encoding.GetBytes(key);
            this.key = encoding.GetString(aes.Key);
            this.iv = encoding.GetString(aes.IV);
            aes.Mode = mode;
            aes.Padding = padding;

        }

        public string Key { get { return key; } }
        public string IV { get { return iv; } }


        private void Validate_KeyIV_Length(string key, string iv)
        {
            //驗證key和iv都必須為128bits或192bits或256bits
            List<int> LegalSizes = new List<int>() { 128, 192, 256 };
            int keyBitSize = encoding.GetBytes(key).Length * 8;
            int ivBitSize = encoding.GetBytes(iv).Length * 8;
            if (!LegalSizes.Contains(keyBitSize) || !LegalSizes.Contains(ivBitSize))
            {
                throw new Exception($@"key或iv的長度不在128bits、192bits、256bits其中一個，輸入的key bits:{keyBitSize},iv bits:{ivBitSize}");
            }
        }

        /// <summary>
        /// 加密後回傳base64String，相同明碼文字編碼後的base64String結果會相同(類似雜湊)，除非變更key或iv
        /// 如果key和iv忘記遺失的話，資料就解密不回來
        /// base64String若使用在Url的話，Web端記得做UrlEncode
        /// </summary>
        /// <param name="plain_text"></param>
        /// <returns></returns>
        public string Encrypt(string plain_text)
        {
            ICryptoTransform transform = aes.CreateEncryptor(encoding.GetBytes(key), encoding.GetBytes(iv));

            byte[] bPlainText = encoding.GetBytes(plain_text);//明碼文字轉byte[]
            byte[] outputData = transform.TransformFinalBlock(bPlainText, 0, bPlainText.Length);//加密
            return Convert.ToBase64String(outputData);
        }
        /// <summary>
        /// 解密後，回傳明碼文字
        /// </summary>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="base64String"></param>
        /// <returns></returns>
        public string Decrypt(string base64String)
        {
            ICryptoTransform transform = aes.CreateDecryptor(encoding.GetBytes(key), encoding.GetBytes(iv));
            byte[] bEnBase64String = null;
            byte[] outputData = null;
            try
            {
                bEnBase64String = Convert.FromBase64String(base64String);//有可能base64String格式錯誤
                outputData = transform.TransformFinalBlock(bEnBase64String, 0, bEnBase64String.Length);//有可能解密出錯
            }
            catch (Exception ex)
            {
                //todo 寫Log
                throw new Exception($@"解密出錯:{ex.Message}");
            }

            //解密成功
            return encoding.GetString(outputData);
        }
    }
}
