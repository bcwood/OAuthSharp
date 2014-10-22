using System.Collections.Specialized;
using System.Configuration;
using System.Net.Http;
using NUnit.Framework;
using WatiN.Core;

namespace OAuthSharp.Tests.Integration
{
	[TestFixture]
	public class OAuth1IntegrationTests
	{
		/// <summary>
		/// Tests the entire OAuth process, interactively in a web browser using WatiN.
		/// To test the final part of the OAuth process (client.AcquireAccessToken()), it is necessary to send
		/// the user's browser to the appropriate URL (obtained from client.GetAuthorizeTokenRedirectUrl())
		/// to have them login and authorize the application.
		/// </summary>
		[TestCase(OAuth1Request.SIGNATURE_METHOD_PLAINTEXT, TestName = "PLAINTEXT")]
		[TestCase(OAuth1Request.SIGNATURE_METHOD_HMAC_SHA1, TestName = "HMAC-SHA1")]
		public void OAuthProcessInteractive(string signatureMethod)
		{
			// get request token
			var tokenRequest = new OAuth1TokenRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, TestData.CALLBACK_URL_OUT_OF_BAND);
			tokenRequest.SignatureMethod = signatureMethod;

			var client = new OAuth1Client();
			var tokenResponse = client.AcquireRequestToken(TestData.OAUTH_URL_GET_REQUEST_TOKEN, tokenRequest);

			// get url to authorize token
			string url = client.GetAuthorizeTokenRedirectUrl(TestData.OAUTH_URL_AUTHORIZE_TOKEN, tokenResponse.Token, TestData.APPLICATION_NAME);

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
				var accessRequest = new OAuth1AccessRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, token, tokenResponse.TokenSecret, verifier);
				accessRequest.SignatureMethod = signatureMethod;

				var accessResponse = client.AcquireAccessToken(TestData.OAUTH_URL_GET_ACCESS_TOKEN, accessRequest);

				Assert.That(accessResponse.Token, Is.Not.Null.Or.Empty);
				Assert.That(accessResponse.TokenSecret, Is.Not.Null.Or.Empty);

				// TODO: prove token is valid by calling API?
			}
		}
	}
}
