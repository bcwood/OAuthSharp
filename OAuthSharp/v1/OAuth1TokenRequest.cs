﻿namespace OAuthSharp
{
    public class OAuth1TokenRequest : OAuth1Request
    {
        /// <summary>
        /// The URL in your application where users will be sent after authorization.
        /// </summary>
        [Parameter(Key = "callback")]
        public string ReturnUrl { get; private set; }

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
        }
    }
}
