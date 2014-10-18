using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace OAuthSharp
{
    public abstract class OAuthRequest : RequestParameters
    {
        public const string SIGNATURE_METHOD_SHA1 = "HMAC-SHA1";
        public const string SIGNATURE_METHOD_PLAINTEXT = "PLAINTEXT";

        /// <summary>
        /// Your applicatin's key for consuming the API.
        /// </summary>
        [Parameter(Key = "consumer_key")]
        public string ConsumerKey { get; protected set; }

        /// <summary>
        /// Your application's secret for consuming the API.
        /// </summary>
        [Parameter(Key = "consumer_secret")]
        public string ConsumerSecret { get; protected set; }

        [Parameter(Key = "signature_method")]
        public string SignatureMethod { get; protected set; }

        [Parameter(Key = "signature")]
        public string Signature { get; protected set; }

        [Parameter(Key = "token")]
        public string Token { get; set; }

        [Parameter(Key = "token_secret")]
        public string TokenSecret { get; set; }

        [Parameter(Key = "version")]
        public string Version { get; private set; }

        public OAuthRequest(string consumerKey, string consumerSecret)
        {
            Ensure.ArgumentNotNullOrEmptyString(consumerKey, "consumerKey");
            Ensure.ArgumentNotNullOrEmptyString(consumerSecret, "consumerSecret");

            this.ConsumerKey = consumerKey;
            this.ConsumerSecret = consumerSecret;
            this.SignatureMethod = SIGNATURE_METHOD_PLAINTEXT;
            this.Version = "1.0";

            this.Token = string.Empty;
            this.TokenSecret = string.Empty;
        }

        internal void SignRequest(string url)
        {
            Ensure.ArgumentNotNullOrEmptyString(this.SignatureMethod, "SignatureMethod");

            string signatureBase = this.GetSignatureBase(url);

            if (this.SignatureMethod == SIGNATURE_METHOD_SHA1)
            {
                var hash = this.GetHash();

                byte[] dataBuffer = Encoding.ASCII.GetBytes(signatureBase);
                byte[] hashBytes = hash.ComputeHash(dataBuffer);

                this.Signature = Convert.ToBase64String(hashBytes);
            }
            else if (this.SignatureMethod == SIGNATURE_METHOD_PLAINTEXT)
            {
                this.Signature = string.Format("{0}&{1}",
                                               UrlEncode(this.ConsumerSecret),
                                               UrlEncode(this.TokenSecret));
            }
        }

        /// <summary>
        /// Formats the list of request parameters into "signature base" string as
        /// defined by RFC 5849.  This will then be MAC'd with a suitable hash.
        /// </summary>
        private string GetSignatureBase(string url)
        {
            // normalize the URI
            var uri = new Uri(url);
            var normUrl = string.Format("{0}://{1}", uri.Scheme, uri.Host);

            if (!((uri.Scheme == "http" && uri.Port == 80) || (uri.Scheme == "https" && uri.Port == 443)))
                normUrl += ":" + uri.Port;

            normUrl += uri.AbsolutePath;

            // the sigbase starts with the method and the encoded URI
            var sb = new StringBuilder();
            sb.AppendFormat("POST&{0}&", UrlEncode(normUrl));

            var parameters = ExtractQueryParameters(uri.Query);

            foreach (var param in this.ToParametersDictionary())
            {
                // Exclude all oauth params that are secret or
                // signatures; any secrets should be kept to ourselves,
                // and any existing signature will be invalid.
                if (!string.IsNullOrEmpty(param.Value) &&
                    !param.Key.EndsWith("_secret") &&
                    !param.Key.EndsWith("signature"))
                    parameters.Add("oauth_" + param.Key, param.Value);
            }

            // concat params
            var paramBuilder = new StringBuilder();
            foreach (var item in parameters.OrderBy(x => x.Key))
            {
                // even "empty" params need to be encoded this way.
                paramBuilder.AppendFormat("{0}={1}&", item.Key, item.Value);
            }

            // append the UrlEncoded version of that string to the sigbase
            sb.Append(UrlEncode(paramBuilder.ToString().TrimEnd('&')));

            return sb.ToString();
        }

        /// <summary>
        /// Extracts all query string parameters from a URL that are not related to OAuth (not beginning with "oauth_").
        /// </summary>
        private Dictionary<string, string> ExtractQueryParameters(string queryString)
        {
            if (queryString.StartsWith("?"))
                queryString = queryString.Remove(0, 1);

            var result = new Dictionary<string, string>();

            if (string.IsNullOrEmpty(queryString))
                return result;

            foreach (string s in queryString.Split('&'))
            {
                if (!string.IsNullOrEmpty(s) && !s.StartsWith("oauth_"))
                {
                    if (s.IndexOf('=') > -1)
                    {
                        string[] temp = s.Split('=');
                        result.Add(temp[0], temp[1]);
                    }
                    else
                        result.Add(s, string.Empty);
                }
            }

            return result;
        }

        private HashAlgorithm GetHash()
        {
            if (this.SignatureMethod != SIGNATURE_METHOD_SHA1)
                throw new NotImplementedException("Hashing only implemented for HMAC-SHA1.");

            string keystring = string.Format("{0}&{1}",
                                             UrlEncode(this.ConsumerSecret),
                                             UrlEncode(this.TokenSecret));
            var hmacsha1 = new HMACSHA1
            {
                Key = Encoding.ASCII.GetBytes(keystring)
            };

            return hmacsha1;
        }

        /// <summary>
        /// Formats the list of request parameters suitable for use in the Authorization header of the request.
        /// </summary>
        /// <returns>An encoded string representing the parameters</returns>
        internal string EncodeRequestParameters()
        {
            var sb = new StringBuilder();

            foreach (var item in this.ToParametersDictionary().OrderBy(x => x.Key))
            {
                if (!string.IsNullOrEmpty(item.Value) && !item.Key.EndsWith("secret"))
                    sb.AppendFormat("oauth_{0}=\"{1}\", ",
                                    item.Key,
                                    UrlEncode(item.Value));
            }

            return sb.ToString().TrimEnd(' ').TrimEnd(',');
        }

        /// <summary>
        ///   This is an OAuth-compliant Url Encoder.  The default .NET
        ///   encoder outputs the percent encoding in lower case.  While this
        ///   is not a problem with the percent encoding defined in RFC 3986,
        ///   OAuth (RFC 5849) requires that the characters be upper case.
        /// </summary>
        private static string UrlEncode(string value)
        {
            const string UNRESERVED_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

            var encoded = new StringBuilder();

            foreach (char c in value)
            {
                if (UNRESERVED_CHARS.IndexOf(c) >= 0)
                    encoded.Append(c);
                else
                    encoded.Append('%' + string.Format("{0:X2}", (int)c));
            }

            return encoded.ToString();
        }
    }
}
