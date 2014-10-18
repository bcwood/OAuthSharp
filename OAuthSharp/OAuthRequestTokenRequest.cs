namespace OAuthSharp
{
    public class OAuthRequestTokenRequest : OAuthRequest
    {
        /// <summary>
        /// The URL in your application where users will be sent after authorization.
        /// </summary>
        [Parameter(Key = "callback")]
        public string ReturnUrl { get; set; }

        public OAuthRequestTokenRequest(string consumerKey, string consumerSecret)
            : base(consumerKey, consumerSecret)
        {
        }
    }
}
