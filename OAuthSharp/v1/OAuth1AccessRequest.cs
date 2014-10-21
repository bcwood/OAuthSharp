namespace OAuthSharp
{
    public class OAuth1AccessRequest : OAuth1Request
    {
        [Parameter(Key = "verifier")]
        public string Verifier { get; set; }

        public OAuth1AccessRequest(string consumerKey, string consumerSecret) 
            : base(consumerKey, consumerSecret)
        {
        }
    }
}
