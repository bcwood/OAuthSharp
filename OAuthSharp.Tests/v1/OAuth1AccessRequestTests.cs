using System;
using NUnit.Framework;

namespace OAuthSharp.Tests
{
	[TestFixture]
	public class OAuth1AccessRequestTests
	{
		private const string TOKEN = "testToken";
		private const string TOKEN_SECRET = "testTokenSecret";
		private const string VERIFIER = "testVerifier";

		[Test]
		public void Constructor_ValidParameters_DoesNotThrow()
		{
			Assert.DoesNotThrow(() => new OAuth1AccessRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, TOKEN, TOKEN_SECRET, VERIFIER));
		}

		[Test]
		public void Constructor_NullParameter_ThrowsArgumentNullException()
		{
			Assert.Throws<ArgumentNullException>(() => new OAuth1AccessRequest(null, TestData.CONSUMER_SECRET, TOKEN, TOKEN_SECRET, VERIFIER));
			Assert.Throws<ArgumentNullException>(() => new OAuth1AccessRequest(TestData.CONSUMER_KEY, null, TOKEN, TOKEN_SECRET, VERIFIER));
			Assert.Throws<ArgumentNullException>(() => new OAuth1AccessRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, null, TOKEN_SECRET, VERIFIER));
			Assert.Throws<ArgumentNullException>(() => new OAuth1AccessRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, TOKEN, null, VERIFIER));
			Assert.Throws<ArgumentNullException>(() => new OAuth1AccessRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, TOKEN, TOKEN_SECRET, null));
		}

		[Test]
		public void Constructor_EmptyParameter_ThrowsArgumentException()
		{
			Assert.Throws<ArgumentException>(() => new OAuth1AccessRequest(string.Empty, TestData.CONSUMER_SECRET, TOKEN, TOKEN_SECRET, VERIFIER));
			Assert.Throws<ArgumentException>(() => new OAuth1AccessRequest(TestData.CONSUMER_KEY, string.Empty, TOKEN, TOKEN_SECRET, VERIFIER));
			Assert.Throws<ArgumentException>(() => new OAuth1AccessRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, string.Empty, TOKEN_SECRET, VERIFIER));
			Assert.Throws<ArgumentException>(() => new OAuth1AccessRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, TOKEN, string.Empty, VERIFIER));
			Assert.Throws<ArgumentException>(() => new OAuth1AccessRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, TOKEN, TOKEN_SECRET, string.Empty));
		}

		//[Test]
		//public void HashKey_ReturnsConsumerSecretAmpersandTokenSecret()
		//{
		//	var request = new OAuth1AccessRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, TOKEN, TOKEN_SECRET, VERIFIER);

		//	Assert.That(request.HashKey, Is.EqualTo(string.Format("{0}&{1}", TestData.CONSUMER_SECRET, TOKEN_SECRET)));
		//}
	}
}
