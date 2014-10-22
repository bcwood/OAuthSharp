using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace OAuthSharp
{
    public abstract class OAuth1Request : RequestParameters
    {
	    public const string SIGNATURE_METHOD_PLAINTEXT = "PLAINTEXT";
		public const string SIGNATURE_METHOD_HMAC_SHA1 = "HMAC-SHA1";

		/// <summary>
        /// Your application's key for consuming the API.
        /// </summary>
        [Parameter(Key = "consumer_key")]
        public string ConsumerKey { get; protected set; }

        /// <summary>
        /// Your application's secret for consuming the API.
        /// </summary>
        [Parameter(Key = "consumer_secret")]
        public string ConsumerSecret { get; protected set; }

        /// <summary>
        /// The signature method name to use for the request (must be one of: PLAINTEXT, HMAC-SHA1)
        /// </summary>
        [Parameter(Key = "signature_method")]
		public string SignatureMethod { get; set; }

		/// <summary>
		/// The signature generated based on the specified SignatureMethod.
		/// </summary>
        [Parameter(Key = "signature")]
        public string Signature { get; private set; }

		/// <summary>
		/// OAuth version (1.0).
		/// </summary>
        [Parameter(Key = "version")]
		protected string Version { get; private set; }

		//private SignatureMethod _signatureMethod;

		///// <summary>
		///// The signature method to use for the request.
		///// </summary>
		//public SignatureMethod SignatureMethod
		//{
		//	get { return _signatureMethod; }
		//	set 
		//	{ 
		//		_signatureMethod = value;
		//		// convert the enum to the corresponding OAuth signature method name
		//		this.SignatureMethodName = _signatureMethod.ToString().ToUpper().Replace("_", "-");
		//	}
		//}

        protected OAuth1Request(string consumerKey, string consumerSecret)
        {
            Ensure.ArgumentNotNullOrEmptyString(consumerKey, "consumerKey");
            Ensure.ArgumentNotNullOrEmptyString(consumerSecret, "consumerSecret");

            this.ConsumerKey = consumerKey;
            this.ConsumerSecret = consumerSecret;
            this.SignatureMethod = SIGNATURE_METHOD_PLAINTEXT;
            this.Version = "1.0";
        }

		/// <summary>
		/// Submits the request to the specified <paramref name="url"/>.
		/// </summary>
		/// <param name="url">OAuth endpoint.</param>
		/// <returns><see cref="OAuth1Response" /> instance.</returns>
		internal OAuth1Response SubmitRequest(string url)
		{
			var authHeader = GetAuthorizationHeader(url);

			var request = (HttpWebRequest) WebRequest.Create(url);
			request.Headers.Add("Authorization", authHeader);
			request.Method = "POST";

			try
			{
				using (var response = (HttpWebResponse) request.GetResponse())
				{
					using (var reader = new StreamReader(response.GetResponseStream()))
					{
						return new OAuth1Response(reader.ReadToEnd());
					}
				}
			}
			catch (WebException ex)
			{
				// get response body in case of 500 server error
				using (var stream = ex.Response.GetResponseStream())
				{
					using (var reader = new StreamReader(stream))
					{
						string errorMessage = reader.ReadToEnd();
						throw new WebException(ex.Message + " (" + errorMessage + ")", ex);
					}
				}
			}
		}

		/// <summary>
		/// Generates the authorization header for the specified <paramref name="url"/> and (optional) <paramref name="realm"/>.
		/// </summary>
		private string GetAuthorizationHeader(string url, string realm = null)
		{
			this.SignRequest(url);

			string encodedParams = this.EncodeRequestParameters();

			return (string.IsNullOrEmpty(realm))
				? "OAuth " + encodedParams
				: string.Format("OAuth realm=\"{0}\", {1}", realm, encodedParams);
		}

        /// <summary>
        /// Signs the request using the appropriate signature method.
        /// </summary>
        private void SignRequest(string url)
        {
	        string tokenSecret = this is OAuth1AccessRequest ? (this as OAuth1AccessRequest).TokenSecret : string.Empty;
			string hashBase = string.Format("{0}&{1}",
											UrlEncode(this.ConsumerSecret),
											UrlEncode(tokenSecret));

			switch (this.SignatureMethod)
			{
				case SIGNATURE_METHOD_PLAINTEXT:
					this.Signature = hashBase;
					break;

				case SIGNATURE_METHOD_HMAC_SHA1:
					string signatureBase = this.GetSignatureBase(url);
					byte[] dataBuffer = Encoding.ASCII.GetBytes(signatureBase);
					
					var sha1 = new HMACSHA1 { Key = Encoding.ASCII.GetBytes(hashBase) };
					byte[] hashBytes = sha1.ComputeHash(dataBuffer);

					this.Signature = Convert.ToBase64String(hashBytes);
					break;

				default:
					throw new NotSupportedException("Unsupported signature method: " + this.SignatureMethod);
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
        ///   This is an OAuth-compliant URL Encoder.  The default .NET
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

		//private string GenerateTimeStamp()
		//{
		//    TimeSpan ts = DateTime.UtcNow - _epoch;
		//    return Convert.ToInt64(ts.TotalSeconds).ToString();
		//}

		///// <summary>
		///// Generate an OAuth nonce.
		///// </summary>
		///// <remarks>
		/////     According to RFC 5849, A nonce is a random string,
		/////     uniquely generated by the client to allow the server to
		/////     verify that a request has never been made before and
		/////     helps prevent replay attacks when requests are made over
		/////     a non-secure channel.  The nonce value MUST be unique
		/////     across all requests with the same timestamp, client
		/////     credentials, and token combinations.
		///// </remarks>
		//private string GenerateNonce()
		//{
		//    var sb = new StringBuilder();

		//    for (int i = 0; i < 8; i++)
		//    {
		//        int g = _random.Next(3);
		//        switch (g)
		//        {
		//            case 0:
		//                // lowercase alpha
		//                sb.Append((char)(_random.Next(26) + 97), 1);
		//                break;
		//            default:
		//                // numeric digits
		//                sb.Append((char)(_random.Next(10) + 48), 1);
		//                break;
		//        }
		//    }

		//    return sb.ToString();
		//}

		//private void NewRequest()
		//{
		//    //this.Nonce = GenerateNonce();
		//    //this.Timestamp = GenerateTimeStamp();
		//}

		//private static readonly DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0);
		//private Random _random;
    }

	public enum SignatureMethod
	{
		Plaintext,
		Hmac_Sha1
	}
}
