using System.IO;
using System.Net;

namespace OAuthSharp
{
    public abstract class OAuth1Request : RequestParameters
    {
        protected abstract string HashKey { get; }

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
		public virtual string SignatureMethod { get; set; }

		/// <summary>
		/// The signature generated based on the specified SignatureMethod.
		/// </summary>
        [Parameter(Key = "signature")]
        public string Signature { get; private set; }

		/// <summary>
		/// Generated nonce to be used as part of Signature.
		/// </summary>
		[Parameter(Key = "nonce")]
		public string Nonce { get; private set; }

		/// <summary>
		/// Generated timestamp to be used as part of Signature.
		/// </summary>
		[Parameter(Key = "timestamp")]
		public string Timestamp { get; private set; }

		/// <summary>
		/// OAuth version (1.0).
		/// </summary>
        [Parameter(Key = "version")]
		public string Version { get; private set; }

        protected OAuth1Request(string consumerKey, string consumerSecret)
        {
            Ensure.ArgumentNotNullOrEmptyString(consumerKey, "consumerKey");
            Ensure.ArgumentNotNullOrEmptyString(consumerSecret, "consumerSecret");

            this.ConsumerKey = consumerKey;
            this.ConsumerSecret = consumerSecret;
            this.SignatureMethod = OAuth1Constants.SIGNATURE_METHOD_PLAINTEXT;
            this.Version = "1.0";
        }

		/// <summary>
		/// Submits the request to the specified <paramref name="url"/>.
		/// </summary>
		/// <param name="url">OAuth endpoint.</param>
		/// <returns><see cref="OAuth1Response" /> instance.</returns>
		internal OAuth1Response SubmitRequest(string url)
		{
			if (this.SignatureMethod == OAuth1Constants.SIGNATURE_METHOD_HMAC_SHA1)
			{
				this.Nonce = OAuth1.GenerateNonce();
				this.Timestamp = OAuth1.GenerateTimestamp().ToString();
			}

			this.Signature = OAuth1.GetSignature(url, this.ToParametersDictionary(), this.SignatureMethod, this.HashKey);

			var request = (HttpWebRequest) WebRequest.Create(url);
			request.Headers.Add("Authorization", OAuth1.GetAuthorizationHeader(this.ToParametersDictionary()));
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
						throw new WebException(errorMessage, ex);
					}
				}
			}
		}
    }
}
