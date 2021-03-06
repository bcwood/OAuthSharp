﻿namespace OAuthSharp
{
    public class OAuth1Response
    {
		/// <summary>
		/// oauth_token parameter received from application.
		/// </summary>
        public string Token { get; private set; }

		/// <summary>
		/// oauth_token_secret parameter received from application.
		/// </summary>
        public string TokenSecret { get; private set; }

        public OAuth1Response(string response)
        {
            foreach (var pair in response.Split('&'))
            {
                var parts = pair.Split('=');

                switch (parts[0])
                {
                    case "oauth_token":
                        this.Token = parts[1];
                        break;
                    case "oauth_token_secret":
                        this.TokenSecret = parts[1];
                        break;

					// TODO: collect any additional parameters, if present?
                }
            }
        }
    }
}
