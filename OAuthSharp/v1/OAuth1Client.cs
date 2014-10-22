using System;
using System.IO;
using System.Net;
using System.Text;

namespace OAuthSharp
{
    public class OAuth1Client
    {
        //private static readonly DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0);
        //private Random _random;

        //public OAuth1Client()
        //{
        //    _random = new Random();

        //    ////_params["timestamp"] = GenerateTimeStamp();
        //    ////_params["nonce"] = GenerateNonce();
        //}

        /// <summary>
        ///   Acquire an OAuth request token.
        /// </summary>
        /// <param name="oauthTokenRequestUrl">OAuth request token endpoint.</param>
        /// <param name="tokenRequest">OAuthRequestTokenRequest instance.</param>
        /// <returns>
        ///   An OAuth1Response instance that contains the entire text of the response,
        ///   as well as any additional extracted parameters.
        /// </returns>
        public OAuth1Response AcquireRequestToken(string oauthTokenRequestUrl, OAuth1TokenRequest tokenRequest)
        {
            Ensure.ArgumentNotNullOrEmptyString(oauthTokenRequestUrl, "oauthTokenRequestUrl");
            Ensure.ArgumentNotNullOrEmptyString(tokenRequest.ConsumerKey, "ConsumerKey");
            Ensure.ArgumentNotNullOrEmptyString(tokenRequest.ConsumerSecret, "ConsumerSecret");
            Ensure.ArgumentNotNullOrEmptyString(tokenRequest.ReturnUrl, "ReturnUrl");

            //NewRequest();

            // TODO: move the rest of this method into OAuth1Request base class
            var authHeader = GetAuthorizationHeader(oauthTokenRequestUrl, tokenRequest);

            // prepare the token request
            var request = (HttpWebRequest) WebRequest.Create(oauthTokenRequestUrl);
            request.Headers.Add("Authorization", authHeader);
            request.Method = "POST";

            try
            {
                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    using (var reader = new StreamReader(response.GetResponseStream()))
                    {
                        return new OAuth1Response(reader.ReadToEnd());
                    }
                }
            }
            catch (WebException ex)
            {
                // get response body in case of 500 server error
                using (var stream = ex.Response.GetResponseStream())
                {
                    using (var reader = new StreamReader(stream))
                    {
                        string errorMessage = reader.ReadToEnd();
                        throw new WebException(ex.Message + " (" + errorMessage + ")", ex);
                    }
                }
            }
        }

        /// <summary>
        /// Gets the URL to be used for redirecting a user to the application for authorization.
        /// </summary>
        /// <param name="oauthAuthorizeTokenUrl">OAuth authorize token endpoint.</param>
        /// <param name="token">Token received from previous call to AcquireRequestToken.</param>
        /// <param name="applicationName">Your application's name, to be presented to the user when asking for authorization.</param>
        public string GetAuthorizeTokenRedirectUrl(string oauthAuthorizeTokenUrl, string token, string applicationName = null)
        {
            Ensure.ArgumentNotNullOrEmptyString(oauthAuthorizeTokenUrl, "oauthAuthorizeTokenUrl");
            Ensure.ArgumentNotNullOrEmptyString(token, "token");

            var sb = new StringBuilder();
            sb.AppendFormat("{0}?oauth_token={1}", oauthAuthorizeTokenUrl, token);

            if (!string.IsNullOrEmpty(applicationName))
                sb.AppendFormat("&name={0}", applicationName);

            return sb.ToString();
        }

        /// <summary>
        ///   Acquire an OAuth access token.
        /// </summary>
        /// <param name="oauthAccessTokenUrl">OAuth access token endpoint.</param>
        /// <param name="accessRequest">OAuthAccessTokenRequest instance.</param>
        /// <returns>
        ///   An OAuth1Response instance that contains the entire text of the response,
        ///   as well as any additional extracted parameters.
        /// </returns>
        public OAuth1Response AcquireAccessToken(string oauthAccessTokenUrl, OAuth1AccessRequest accessRequest)
        {
            Ensure.ArgumentNotNullOrEmptyString(oauthAccessTokenUrl, "oauthAccessTokenUrl");
            
            //NewRequest();

            // TODO: move the rest of this method into OAuth1Request base class
            var authHeader = GetAuthorizationHeader(oauthAccessTokenUrl, accessRequest);

            // prepare the token request
            var request = (HttpWebRequest) WebRequest.Create(oauthAccessTokenUrl);
            request.Headers.Add("Authorization", authHeader);
            request.Method = "POST";

            try
            {
                using (var response = (HttpWebResponse) request.GetResponse())
                {
                    using (var reader = new StreamReader(response.GetResponseStream()))
                    {
                        return new OAuth1Response(reader.ReadToEnd());
                    }
                }
            }
            catch (WebException ex)
            {
                // get response body in case of 500 server error
                using (var stream = ex.Response.GetResponseStream())
                {
                    using (var reader = new StreamReader(stream))
                    {
                        string errorMessage = reader.ReadToEnd();
                        throw new WebException(ex.Message + " (" + errorMessage + ")", ex);
                    }
                }
            }
        }

        private string GetAuthorizationHeader(string url, OAuth1Request oauthRequest, string realm = null)
        {
            oauthRequest.SignRequest(url);

            string encodedParams = oauthRequest.EncodeRequestParameters();

            return (string.IsNullOrEmpty(realm))
                ? "OAuth " + encodedParams
                : string.Format("OAuth realm=\"{0}\", {1}", realm, encodedParams);
        }

        //private string GenerateTimeStamp()
        //{
        //    TimeSpan ts = DateTime.UtcNow - _epoch;
        //    return Convert.ToInt64(ts.TotalSeconds).ToString();
        //}

        ///// <summary>
        ///// Generate an OAuth nonce.
        ///// </summary>
        ///// <remarks>
        /////     According to RFC 5849, A nonce is a random string,
        /////     uniquely generated by the client to allow the server to
        /////     verify that a request has never been made before and
        /////     helps prevent replay attacks when requests are made over
        /////     a non-secure channel.  The nonce value MUST be unique
        /////     across all requests with the same timestamp, client
        /////     credentials, and token combinations.
        ///// </remarks>
        //private string GenerateNonce()
        //{
        //    var sb = new StringBuilder();

        //    for (int i = 0; i < 8; i++)
        //    {
        //        int g = _random.Next(3);
        //        switch (g)
        //        {
        //            case 0:
        //                // lowercase alpha
        //                sb.Append((char)(_random.Next(26) + 97), 1);
        //                break;
        //            default:
        //                // numeric digits
        //                sb.Append((char)(_random.Next(10) + 48), 1);
        //                break;
        //        }
        //    }

        //    return sb.ToString();
        //}

        //private void NewRequest()
        //{
        //    //this.Nonce = GenerateNonce();
        //    //this.Timestamp = GenerateTimeStamp();
        //}
    }
}
