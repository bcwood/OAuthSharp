using System.Collections.Specialized;
using System.Configuration;
using System.Net.Http;
using NUnit.Framework;
using WatiN.Core;

namespace OAuthSharp.Tests
{
    [TestFixture]
    public class OAuth1ClientTests
    {
        private const string CONSUMER_KEY = "91863bdb08a340af84f6f99b2c03f72c";
        private const string CONSUMER_SECRET = "2073c6272728ed8d5844e9f92a9f73941efd9ca09909bbaf2b3ea29cc52b0c4c";
        private const string CALLBACK_URL = "http://localhost/oauth_callback";
        private const string CALLBACK_URL_OUT_OF_BAND = "oob";
        private const string APPLICATION_NAME = "OAuthSharp";

        private const string OAUTH_URL_GET_REQUEST_TOKEN = "https://trello.com/1/OAuthGetRequestToken";
        private const string OAUTH_URL_AUTHORIZE_TOKEN = "https://trello.com/1/OAuthAuthorizeToken";
        private const string OAUTH_URL_GET_ACCESS_TOKEN = "https://trello.com/1/OAuthGetAccessToken";

        [Test]
        public void AcquireRequestToken()
        {
            var request = new OAuth1TokenRequest(CONSUMER_KEY, CONSUMER_SECRET, CALLBACK_URL);

            var client = new OAuth1Client();
            var response = client.AcquireRequestToken(OAUTH_URL_GET_REQUEST_TOKEN, request);

            Assert.That(response.Token, Is.Not.Null.Or.Empty);
            Assert.That(response.TokenSecret, Is.Not.Null.Or.Empty);
        }

        [Test]
        public void GetAuthorizeTokenRedirectUrl()
        {
            const string TOKEN = "tempauthtoken";

            var client = new OAuth1Client();
            string url = client.GetAuthorizeTokenRedirectUrl(OAUTH_URL_AUTHORIZE_TOKEN, TOKEN, APPLICATION_NAME);

            Assert.That(url, Is.Not.Null.Or.Empty);
            Assert.That(url, Contains.Substring("?oauth_token=" + TOKEN));
            Assert.That(url, Contains.Substring("&name=" + APPLICATION_NAME));
        }

        /// <summary>
        /// Tests the entire OAuth process, interactively in a web browser using WatiN.
        /// Normally, I wouldn't include this kind of a test as  "unit" test, but it's
        /// the only way of truly testing the last part of the process.
        /// To perform the last part of the process, it is necessary to send the user's
        /// browser to the appropriate URL (obtained from client.GetAuthorizeTokenRedirectUrl())
        /// to have them login and authorize our application.
        /// </summary>
        [Test]
        public void OAuthProcessInteractive()
        {
            // get request token
            var tokenRequest = new OAuth1TokenRequest(CONSUMER_KEY, CONSUMER_SECRET, CALLBACK_URL_OUT_OF_BAND);

            var client = new OAuth1Client();
            var tokenResponse = client.AcquireRequestToken(OAUTH_URL_GET_REQUEST_TOKEN, tokenRequest);

            // get url to authorize token
            string url = client.GetAuthorizeTokenRedirectUrl(OAUTH_URL_AUTHORIZE_TOKEN, tokenResponse.Token, APPLICATION_NAME);

            // use WatiN to send "user" to approve access
            using (var browser = new IE(url))
            {
                var loginLink = browser.Link(Find.ByClass("button primary"));

                // check for existence of login link
                if (loginLink != null)
                {
                    loginLink.Click();

                    // fill login form
                    browser.ElementOfType<TextFieldExtended>("user").Value = ConfigurationManager.AppSettings["TRELLO_USERNAME"];
                    browser.TextField("password").Value = ConfigurationManager.AppSettings["TRELLO_PASSWORD"];
                    browser.Button("login").Click();
                }

                // click "approve"
                browser.Button(Find.ByName("approve")).Click();

                // extract temporary oauth_token & oauth_verifier params from query string
                NameValueCollection queryParams = browser.Uri.ParseQueryString();
                string token = queryParams["oauth_token"];
                string verifier = queryParams["oauth_verifier"];

                Assert.That(token, Is.Not.Null.Or.Empty);
                Assert.That(verifier, Is.Not.Null.Or.Empty);

                // finally, get access token
                var accessRequest = new OAuth1AccessRequest(CONSUMER_KEY, CONSUMER_SECRET);
                accessRequest.Token = token;
                accessRequest.Verifier = verifier;
                accessRequest.TokenSecret = tokenResponse.TokenSecret;

                var accessResponse = client.AcquireAccessToken(OAUTH_URL_GET_ACCESS_TOKEN, accessRequest);

                Assert.That(accessResponse.Token, Is.Not.Null.Or.Empty);
                Assert.That(accessResponse.TokenSecret, Is.Not.Null.Or.Empty);

                // TODO: prove token is valid by calling API?
            }
        }
    }
}
