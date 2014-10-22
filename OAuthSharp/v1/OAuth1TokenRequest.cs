﻿namespace OAuthSharp
{
    public class OAuth1TokenRequest : OAuth1Request
    {
        /// <summary>
        /// The URL in your application where users will be sent after authorization.
        /// </summary>
        [Parameter(Key = "callback")]
        public string ReturnUrl { get; set; }

        public OAuth1TokenRequest(string consumerKey, string consumerSecret)
            : base(consumerKey, consumerSecret)
        {
        }
    }
}