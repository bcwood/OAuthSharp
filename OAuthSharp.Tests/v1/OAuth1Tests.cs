using System;
using System.Collections.Generic;
using NUnit.Framework;

namespace OAuthSharp.Tests
{
	[TestFixture]
	public class OAuth1Tests
	{
		[Test]
		public void GenerateNonce_ReturnsNotNull()
		{
			Assert.That(OAuth1.GenerateNonce(), Is.Not.Null.Or.Empty);
		}

		[Test]
		public void GenerateNonce_MultipleCallsReturnUniqueValues()
		{
			string nonce1 = OAuth1.GenerateNonce();
			string nonce2 = OAuth1.GenerateNonce();

			Assert.That(nonce1 != nonce2);
		}

		[Test]
		public void GenerateTimestamp_ReturnsNotNull()
		{
			Assert.That(OAuth1.GenerateTimestamp(), Is.Not.Null);
		}

		[Test]
		public void GenerateTimestamp_ReturnsPositiveNumber()
		{
			Assert.That(OAuth1.GenerateTimestamp(), Is.Positive);
		}

		[Test]
		public void GetSignature_InvalidSignatureMethod_ThrowsNotSupportedException()
		{
			Assert.Throws<NotSupportedException>(() => OAuth1.GetSignature("url", null, "RSA", "hashKey"));
		}

		[Test]
		public void GetSignature_PlaintextSignatureMethod_ReturnsHashKey()
		{
			string hashKey = "mysecrethashkey";

			string signature = OAuth1.GetSignature("url", null, OAuth1Request.SIGNATURE_METHOD_PLAINTEXT, hashKey);

			Assert.That(signature, Is.EqualTo(hashKey));
		}

		[Test]
		public void NormalizeUrl_Tests()
		{
			Assert.That(OAuth1.NormalizeUrl("http://www.example.com"), Is.EqualTo("http://www.example.com/"));
			Assert.That(OAuth1.NormalizeUrl("https://www.example.com:8443"), Is.EqualTo("https://www.example.com:8443/"));
			Assert.That(OAuth1.NormalizeUrl("http://www.example.com/index?abc=123"), Is.EqualTo("http://www.example.com/index"));
		}

		[Test]
		public void GetAuthorizationHeader_AppendsOAuthPrefixToParamNames()
		{
			var parameters = new Dictionary<string, string>
				{
					{ "consumer_key", TestData.CONSUMER_KEY },
					{ "token", "testtoken" }
				};

			Assert.That(OAuth1.GetAuthorizationHeader(parameters), Is.EqualTo(string.Format("OAuth oauth_consumer_key=\"{0}\", oauth_token=\"{1}\"", TestData.CONSUMER_KEY, "testtoken")));
		}

		[Test]
		public void GetAuthorizationHeader_IgnoresTokenSecretParam()
		{
			var parameters = new Dictionary<string, string>
				{
					{ "consumer_key", TestData.CONSUMER_KEY },
					{ "token", "testtoken" },
					{ "token_secret", "testtokensecret" }
				};

			Assert.That(OAuth1.GetAuthorizationHeader(parameters), Is.EqualTo(string.Format("OAuth oauth_consumer_key=\"{0}\", oauth_token=\"{1}\"", TestData.CONSUMER_KEY, "testtoken")));
		}
	}
}
