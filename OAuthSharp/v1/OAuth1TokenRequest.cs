namespace OAuthSharp
{
    public class OAuth1TokenRequest : OAuth1Request
    {
        /// <summary>
        /// The URL in your application where users will be sent after authorization.
        /// </summary>
        [Parameter(Key = "callback")]
        public string ReturnUrl { get; private set; }

		[Parameter(Key = "signature_method")]
		public override string SignatureMethod
	    {
			// token request always uses plaintext, as there is no token_secret yet
			get { return SIGNATURE_METHOD_PLAINTEXT; }
	    }

		/// <summary>
		/// Initializes a new token request.
		/// </summary>
		/// <param name="consumerKey">Your application's key for consuming the API.</param>
		/// <param name="consumerSecret">Your application's secret for consuming the API.</param>
		/// <param name="returnUrl">The URL in your application where users will be sent after authorization.</param>
        public OAuth1TokenRequest(string consumerKey, string consumerSecret, string returnUrl)
            : base(consumerKey, consumerSecret)
        {
			Ensure.ArgumentNotNullOrEmptyString(returnUrl, "returnUrl");

            this.ReturnUrl = returnUrl;

			// TODO: allow specifying additional parameters specific to an application (scope, expiration, etc.)
        }

		protected override string HashKey
	    {
			get { return string.Format("{0}&", OAuth1.UrlEncode(this.ConsumerSecret)); }
	    }
    }
}
