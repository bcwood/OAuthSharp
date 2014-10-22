namespace OAuthSharp
{
    public class OAuth1AccessRequest : OAuth1Request
    {
		[Parameter(Key = "token")]
		public string Token { get; set; }

		[Parameter(Key = "token_secret")]
		public string TokenSecret { get; set; }

        [Parameter(Key = "verifier")]
        public string Verifier { get; set; }

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
    }
}
