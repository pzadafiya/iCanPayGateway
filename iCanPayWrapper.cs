using NLFSG.Common.Utils;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace NLFSG.BLL.Helper
{
    public class iCanPayWrapper
    {
        private static String _API_URL = null;
        private static String _3DSv_API_URL = null;
        private static String _SECRET_KEY = null;
        private static Dictionary<string, string> _PARAMS = null;
        private static String _API_TYPE = null;

        public iCanPayPaymentHelper(String secretKey, Dictionary<string, string> param, String type) 
        {
            _API_URL = "https://pay.icanpay.cn.com/pay/authorize_payment";
            _3DSv_API_URL = "https://pay.icanpay.cn.com/pay/authorize3dsv_payment";
            _SECRET_KEY = secretKey;// getKey(secretKey);
            _PARAMS = param;
            _API_TYPE = type;
            validatePayload();
        }

        public string payment()
        {
            Dictionary<string, string> payloadList = new Dictionary<string, string>();

            payloadList.Add("ccn", (string)_PARAMS["ccn"]);
            payloadList.Add("expire", _PARAMS["exp_month"] + "/" + _PARAMS["exp_year"]);
            payloadList.Add("cvc", (String)_PARAMS["cvc_code"]);
            payloadList.Add("firstname", (String)_PARAMS["firstname"]);
            payloadList.Add("lastname", (String)_PARAMS["lastname"]);

            string Transaction_Hash = (string)_PARAMS["transaction_hash"];

            String encryptedString = encrypt(payloadList);
            _PARAMS.Add("card_info", encryptedString);

            _PARAMS.Remove("ccn");
            _PARAMS.Remove("cvc_code");
            _PARAMS.Remove("firstname");
            _PARAMS.Remove("lastname");
            _PARAMS.Remove("exp_year");
            _PARAMS.Remove("exp_month");
            _PARAMS.Remove("transaction_hash");

            if (_API_TYPE.Equals("3DSV"))
            {
                try
                {
                    _PARAMS["success_url"] = UrlEncode((string)_PARAMS["success_url"]);
                    _PARAMS["fail_url"] = UrlEncode((string)_PARAMS["fail_url"]);
                    _PARAMS["notify_url"] = UrlEncode((string)_PARAMS["notify_url"]);

                }
                catch (Exception e){}
            }

            String signature = "";

            SortedSet<string> keys = new SortedSet<string>(_PARAMS.Keys);
            foreach (string key in keys)
            {
                if (key.Equals("signature"))
                    continue;
                String value = (String)_PARAMS[key];
                signature = signature + value;
            }

            if (_PARAMS.ContainsKey("signature")) _PARAMS.Remove("signature");

            String signatureString = signature + "" + _SECRET_KEY;// _SECRET_KEY;
            string strSHA1 = GenerateSHA1(signatureString);
            _PARAMS.Add("signature", strSHA1.ToLower());
            _PARAMS.Add("transaction_hash", Transaction_Hash);

            if (_API_TYPE.Equals("API"))
            {
                _PARAMS.Add("tr_mode", "API");
                try
                {
                    // For logging of rhe Params
                    try
                    {
                        string strDic = string.Join(";", _PARAMS.Select(x => x.Key + "=" + x.Value).ToArray());
                        BLL.ErrorLogger.LogErrorInTextFile(strDic, "CcDetailParamsResponse");
                    }
                    catch{}

                    String response = "";
                    response = HTTPPostReponse(_API_URL, _PARAMS);
                    return response;
                }
                catch (Exception e)
                {
                    throw e;
                }
            }
            else if (_API_TYPE.Equals("3DSV"))
            {
                 _PARAMS.Add("tr_mode", "API3DSv");
                string jsonString = Newtonsoft.Json.JsonConvert.SerializeObject(_PARAMS);
                byte[] binary = Encoding.UTF8.GetBytes(jsonString);
                string strEncoded = Convert.ToBase64String(binary);
                string strRedirectURL = _3DSv_API_URL + "?request=" + strEncoded;
                object objData = new { status = 1, redirect_url = strRedirectURL };
                return Newtonsoft.Json.JsonConvert.SerializeObject(objData);
            }
            return "";
        }

        private static string encrypt(Dictionary<string, string> payload)
        {
            byte[] encrypted = null;
            byte[] encryptIV = null;
            try
            {

                using (RijndaelManaged myRijndael = new RijndaelManaged())
                {
                    myRijndael.Key = Encoding.UTF8.GetBytes(getKey(_SECRET_KEY));
                    myRijndael.GenerateIV();
                    encryptIV = myRijndael.IV;

                    string strImplodeValue = ImplodeWithKeys(payload);

                    // Encrypt the string to an array of bytes. 
                    //encrypted = EncryptStringToBytes(strImplodeValue, myRijndael.Key, myRijndael.IV);
                    encrypted = EncryptString(strImplodeValue, myRijndael.Key, myRijndael.IV);
                }
            }
            catch (Exception e)
            {
                throw e;
            }
            if (encrypted != null)
            {
               
                var merged = new byte[encryptIV.Length + encrypted.Length];
                encryptIV.CopyTo(merged, 0);
                encrypted.CopyTo(merged, encryptIV.Length);
                string ArrayToString = Convert.ToBase64String(merged);
                return ArrayToString;
            }

            return "";
        }

        public static byte[] EncryptString(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                rijAlg.Padding = PaddingMode.Zeros;
                rijAlg.Mode = CipherMode.CBC;
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            swEncrypt.Write(plainText);
                            if (plainText.Length < 16)
                            {
                                for (int i = plainText.Length; i < 16; i++)
                                    swEncrypt.Write((byte)0x0);
                            }
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }
        private static string ImplodeWithKeys(Dictionary<string, string> payload)
        {
            string strReturnValue = string.Empty;
            if (payload.Count > 0)
            {
                foreach (KeyValuePair<string, string> key in payload)
                    strReturnValue += key.Key + "||" + key.Value + "__";

                strReturnValue = strReturnValue.Substring(0, strReturnValue.Length - 2);
            }
            return strReturnValue;
            //if (count($array) > 0)
            //{
            //    foreach ($array as $key => $value) {
            //    $return .= $key. '||'. $value. '__';
            //    }
            //$return = substr($return, 0, strlen($return) -2);
            //}
            //return $return;
        }

        static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.Mode = CipherMode.ECB;
                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }

        private string HTTPPostReponse(string requestURL, Dictionary<string, string> postDataParams)
        {
            try
            {
                using (var client = new WebClient())
                {
                    var postValues = new NameValueCollection();
                    foreach (KeyValuePair<string, string> dic in postDataParams)
                        postValues[dic.Key] = dic.Value;

                    var response = client.UploadValues(requestURL, postValues);
                    var responseString = Encoding.Default.GetString(response);
                    string[] straryResponse = responseString.Split('&');
                    var dict = HttpUtility.ParseQueryString(responseString);
                    Dictionary<string, string> objDic = new Dictionary<string, string>();
                    objDic = dict.AllKeys.ToDictionary(k => k, k => dict[k]);
                    //foreach (string item in straryResponse)
                    //    objDic.Add(item.Substring(0, item.IndexOf('=') + 1), item.Substring(item.IndexOf("=")));

                    return Newtonsoft.Json.JsonConvert.SerializeObject(objDic);
                }

            }
            catch (Exception ex)
            {

                throw;
            }

        }

        private string mapToQueryString(Dictionary<string, string> map)
        {
            StringBuilder sbStr = new StringBuilder();

            foreach (KeyValuePair<string, string> entry in map)
            {
                var key = entry.Key;
                sbStr.Append(entry.Key);
                sbStr.Append("=");
                try
                {
                    sbStr.Append(RestSharp.Contrib.HttpUtility.UrlDecode(entry.Value, Encoding.UTF8));
                }
                catch (Exception e) { }
                sbStr.Append("&");
            }

            return sbStr.ToString();
        }

        private Dictionary<string, string> getQueryParams(String url)
        {
            try
            {
                Dictionary<string, string> parameters = new Dictionary<string, string>();
                String[] urlParts = url.Split('?');
                if (urlParts.Length > 1)
                {
                    String query = urlParts[1];
                    foreach (var param in query.Split('&'))
                    {
                        String[] pair = param.Split('=');
                        String key = RestSharp.Contrib.HttpUtility.UrlDecode(pair[0], Encoding.UTF8);
                        String value = "";
                        if (pair.Length > 1)
                        {
                            value = RestSharp.Contrib.HttpUtility.UrlDecode(pair[1], Encoding.UTF8);
                            parameters.Add(key, value);
                        }
                    }
                }
                return parameters;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public static string GenerateSHA1(string ToSHA1)
        {
            byte[] hash = new SHA1CryptoServiceProvider().ComputeHash(
                                 new UTF8Encoding().GetBytes(ToSHA1));
            string str = string.Empty;
            foreach (byte num in hash)
                str = str + string.Format("{0,0:x2}", (object)num);
            return str;
        }

        private static String getKey(String key)
        {

            //String filteredKey = key.Replace("[^A-Za-z0-9]", "").Substring(0, 16);
            string strKey = Regex.Replace(_SECRET_KEY, "[^A-Za-z0-9]", "").Substring(0, 16);
            strKey = strKey.Substring(0, 16);
            //String filteredKey = key.Replace(".", "").Substring(0, 16);

            if (strKey.Length < 16)
                throw new Exception("secretKey can not be less than 16 chars");

            return strKey;
        }

        private bool validatePayload()
        {
            if (_PARAMS.Count() == 0)
            {
                throw new Exception("params can not be empty");
            }

            List<String> requiredParamList = new List<string>();

            if (_API_TYPE.Equals("API"))
            {
                requiredParamList.Add("authenticate_id");
                requiredParamList.Add("authenticate_pw");
                requiredParamList.Add("orderid");
                requiredParamList.Add("transaction_type");
                requiredParamList.Add("amount");
                requiredParamList.Add("currency");
                requiredParamList.Add("ccn");
                requiredParamList.Add("exp_month");
                requiredParamList.Add("exp_year");
                requiredParamList.Add("firstname");
                requiredParamList.Add("lastname");
                requiredParamList.Add("email");
                requiredParamList.Add("street");
                requiredParamList.Add("city");
                requiredParamList.Add("zip");
                requiredParamList.Add("state");
                requiredParamList.Add("country");
                requiredParamList.Add("phone");
                requiredParamList.Add("transaction_hash");
            }
            else if (_API_TYPE.Equals("3DSV"))
            {
                requiredParamList.Add("authenticate_id");
                requiredParamList.Add("authenticate_pw");
                requiredParamList.Add("orderid");
                requiredParamList.Add("transaction_type");
                requiredParamList.Add("amount");
                requiredParamList.Add("currency");
                requiredParamList.Add("ccn");
                requiredParamList.Add("exp_month");
                requiredParamList.Add("exp_year");
                requiredParamList.Add("firstname");
                requiredParamList.Add("lastname");
                requiredParamList.Add("email");
                requiredParamList.Add("street");
                requiredParamList.Add("city");
                requiredParamList.Add("zip");
                requiredParamList.Add("state");
                requiredParamList.Add("country");
                requiredParamList.Add("phone");
                requiredParamList.Add("dob");
                requiredParamList.Add("success_url");
                requiredParamList.Add("fail_url");
                requiredParamList.Add("notify_url");
                requiredParamList.Add("transaction_hash");

            }

            foreach (var key in requiredParamList)
            {
                if (!_PARAMS.ContainsKey(key))
                {
                    throw new Exception(key + "param must have a value");
                }
            }

            return true;
        }

        public string UrlEncode(string url)
        {
            Dictionary<string, string> toBeEncoded = new Dictionary<string, string>() { { "%", "%25" }, { "!", "%21" }, { "#", "%23" }, { " ", "%20" },
    { "$", "%24" }, { "&", "%26" }, { "'", "%27" }, { "(", "%28" }, { ")", "%29" }, { "*", "%2A" }, { "+", "%2B" }, { ",", "%2C" },
    { "/", "%2F" }, { ":", "%3A" }, { ";", "%3B" }, { "=", "%3D" }, { "?", "%3F" }, { "@", "%40" }, { "[", "%5B" }, { "]", "%5D" } };
            Regex replaceRegex = new Regex(@"[%!# $&'()*+,/:;=?@\[\]]");
            MatchEvaluator matchEval = match => toBeEncoded[match.Value];
            string encoded = replaceRegex.Replace(url, matchEval);
            return encoded;
        }
    }
}