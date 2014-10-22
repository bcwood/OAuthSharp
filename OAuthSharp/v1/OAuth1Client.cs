using System;
using System.IO;
using System.Net;
using System.Text;

namespace OAuthSharp
{
    public class OAuth1Client
    {
        /// <summary>
        ///   Acquire an OAuth request token.
        /// </summary>
        /// <param name="endpointUrl">OAuth request token endpoint.</param>
        /// <param name="tokenRequest">OAuthRequestTokenRequest instance.</param>
        /// <returns>
        ///   An OAuth1Response instance that contains the entire text of the response,
        ///   as well as any additional extracted parameters.
        /// </returns>
		public OAuth1Response AcquireRequestToken(string endpointUrl, OAuth1TokenRequest tokenRequest)
        {
			Ensure.ArgumentNotNullOrEmptyString(endpointUrl, "endpointUrl");

            return tokenRequest.SubmitRequest(endpointUrl);
        }

        /// <summary>
        /// Gets the URL to be used for redirecting a user to the application for authorization.
        /// </summary>
		/// <param name="endpointUrl">OAuth authorize token endpoint.</param>
        /// <param name="token">Token received from previous call to AcquireRequestToken.</param>
        /// <param name="applicationName">Your application's name, to be presented to the user when asking for authorization.</param>
		public string GetAuthorizeTokenRedirectUrl(string endpointUrl, string token, string applicationName = null)
        {
			Ensure.ArgumentNotNullOrEmptyString(endpointUrl, "endpointUrl");
            Ensure.ArgumentNotNullOrEmptyString(token, "token");

            var sb = new StringBuilder();
			sb.AppendFormat("{0}?oauth_token={1}", endpointUrl, token);

            if (!string.IsNullOrEmpty(applicationName))
                sb.AppendFormat("&name={0}", applicationName);

            return sb.ToString();
        }

        /// <summary>
        ///   Acquire an OAuth access token.
        /// </summary>
		/// <param name="endpointUrl">OAuth access token endpoint.</param>
        /// <param name="accessRequest">OAuthAccessTokenRequest instance.</param>
        /// <returns>
        ///   An OAuth1Response instance that contains the entire text of the response,
        ///   as well as any additional extracted parameters.
        /// </returns>
		public OAuth1Response AcquireAccessToken(string endpointUrl, OAuth1AccessRequest accessRequest)
        {
			Ensure.ArgumentNotNullOrEmptyString(endpointUrl, "endpointUrl");
            
            return accessRequest.SubmitRequest(endpointUrl);
        }
    }
}
