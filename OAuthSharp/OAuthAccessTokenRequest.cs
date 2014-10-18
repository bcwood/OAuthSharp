namespace OAuthSharp
{
    public class OAuthAccessTokenRequest : OAuthRequest
    {
        [Parameter(Key = "verifier")]
        public string Verifier { get; set; }

        public OAuthAccessTokenRequest(string consumerKey, string consumerSecret) 
            : base(consumerKey, consumerSecret)
        {
        }
    }
}
