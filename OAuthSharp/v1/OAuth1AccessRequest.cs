namespace OAuthSharp
{
    public class OAuth1AccessRequest : OAuth1Request
    {
		/// <summary>
		/// oauth_token received back in browser after user authorization.
		/// </summary>
		[Parameter(Key = "token")]
		public string Token { get; private set; }

		/// <summary>
		/// oauth_token_secret received back from the original <see cref="OAuth1TokenRequest"/>.
		/// </summary>
		[Parameter(Key = "token_secret")]
		public string TokenSecret { get; private set; }

		/// <summary>
		/// oauth_verifier received back in browser after user authorization.
		/// </summary>
        [Parameter(Key = "verifier")]
		public string Verifier { get; private set; }

		/// <summary>
		/// Initializes a new access request.
		/// </summary>
		/// <param name="consumerKey">Your application's key for consuming the API.</param>
		/// <param name="consumerSecret">Your application's secret for consuming the API.</param>
		/// <param name="token">oauth_token received back in browser after user authorization.</param>
		/// <param name="tokenSecret">oauth_token_secret received back from the original <see cref="OAuth1TokenRequest"/>.</param>
		/// <param name="verifier">oauth_verifier received back in browser after user authorization.</param>
		public OAuth1AccessRequest(string consumerKey, string consumerSecret, string token, string tokenSecret, string verifier) 
            : base(consumerKey, consumerSecret)
		{
			Ensure.ArgumentNotNullOrEmptyString(token, "token");
			Ensure.ArgumentNotNullOrEmptyString(tokenSecret, "tokenSecret");
			Ensure.ArgumentNotNullOrEmptyString(verifier, "verifier");

			this.Token = token;
			this.TokenSecret = tokenSecret;
			this.Verifier = verifier;
		}

	    protected override string HashKey
	    {
			get 
			{ 
				return string.Format("{0}&{1}", 
									 UrlEncode(this.ConsumerSecret), 
									 UrlEncode(this.TokenSecret)); 
			}
	    }
    }
}
