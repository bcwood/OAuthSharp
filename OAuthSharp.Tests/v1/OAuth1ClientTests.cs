using NUnit.Framework;

namespace OAuthSharp.Tests
{
    [TestFixture]
    public class OAuth1ClientTests
    {
        [Test]
        public void AcquireRequestToken_ResponseContains_TokenAndTokenSecret()
        {
			var request = new OAuth1TokenRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, TestData.CALLBACK_URL);

            var client = new OAuth1Client();
			var response = client.AcquireRequestToken(TestData.OAUTH_URL_GET_REQUEST_TOKEN, request);

            Assert.That(response.Token, Is.Not.Null.Or.Empty);
            Assert.That(response.TokenSecret, Is.Not.Null.Or.Empty);
        }

        [Test]
        public void GetAuthorizeTokenRedirectUrl_UrlContains_OAuthTokenAndApplicationName()
        {
            const string TOKEN = "tempauthtoken";

            var client = new OAuth1Client();
			string url = client.GetAuthorizeTokenRedirectUrl(TestData.OAUTH_URL_AUTHORIZE_TOKEN, TOKEN, TestData.APPLICATION_NAME);

            Assert.That(url, Is.Not.Null.Or.Empty);
            Assert.That(url, Contains.Substring("?oauth_token=" + TOKEN));
			Assert.That(url, Contains.Substring("&name=" + TestData.APPLICATION_NAME));
        }
    }
}
