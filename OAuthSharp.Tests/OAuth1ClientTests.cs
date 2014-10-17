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
        private const string APPLICATION_NAME = "OAuthSharp";

        private const string OAUTH_URL_GET_REQUEST_TOKEN = "https://trello.com/1/OAuthGetRequestToken";
        private const string OAUTH_URL_AUTHORIZE_TOKEN = "https://trello.com/1/OAuthAuthorizeToken";
        private const string OAUTH_URL_GET_ACCESS_TOKEN = "https://trello.com/1/OAuthGetAccessToken";

        [Test]
        public void AcquireRequestToken()
        {
            var client = new OAuth1Client();
            client["consumer_key"] = CONSUMER_KEY;
            client["consumer_secret"] = CONSUMER_SECRET;
            client["callback"] = CALLBACK_URL;

            client.AcquireRequestToken(OAUTH_URL_GET_REQUEST_TOKEN, "POST");

            Assert.That(string.IsNullOrEmpty(client["token"]), Is.False);
        }

        [Test]
        public void GetAuthorizeTokenRedirectUrl()
        {
            var client = new OAuth1Client();
            client["consumer_key"] = CONSUMER_KEY;
            client["consumer_secret"] = CONSUMER_SECRET;
            client["callback"] = CALLBACK_URL;
            client["token"] = "tempauthtoken";

            string url = client.GetAuthorizeTokenRedirectUrl(OAUTH_URL_AUTHORIZE_TOKEN, APPLICATION_NAME);

            Assert.That(string.IsNullOrEmpty(url), Is.False);
            Assert.That(url, Contains.Substring("?oauth_token=" + client["token"]));
            Assert.That(url, Contains.Substring("&name=" + APPLICATION_NAME));
        }

        [Test]
        public void OAuthProcessInteractive()
        {
            var client = new OAuth1Client();
            client["consumer_key"] = CONSUMER_KEY;
            client["consumer_secret"] = CONSUMER_SECRET;
            client["callback"] = "oob";

            client.AcquireRequestToken(OAUTH_URL_GET_REQUEST_TOKEN, "POST");

            string url = client.GetAuthorizeTokenRedirectUrl(OAUTH_URL_AUTHORIZE_TOKEN, APPLICATION_NAME);

            using (var browser = new IE(url))
            {
                var loginLink = browser.Link(Find.ByClass("button primary"));

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

                NameValueCollection queryParams = browser.Uri.ParseQueryString();
                string token = queryParams["oauth_token"];
                string verifier = queryParams["oauth_verifier"];

                Assert.That(string.IsNullOrEmpty(token), Is.False);
                Assert.That(string.IsNullOrEmpty(verifier), Is.False);

                client.AcquireAccessToken(OAUTH_URL_GET_ACCESS_TOKEN, "POST", token, client["token_secret"], verifier);

                Assert.That(string.IsNullOrEmpty(client["token"]), Is.False);
                Assert.That(string.IsNullOrEmpty(client["token_secret"]), Is.False);

                // TODO: prove token is valid by calling API?
            }
        }
    }
}
