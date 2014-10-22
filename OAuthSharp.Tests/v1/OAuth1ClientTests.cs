using NUnit.Framework;

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
    }
}
