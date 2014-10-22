using System;
using NUnit.Framework;

namespace OAuthSharp.Tests
{
	[TestFixture]
	public class OAuth1TokenRequestTests
	{
		private const string CONSUMER_KEY = "91863bdb08a340af84f6f99b2c03f72c";
		private const string CONSUMER_SECRET = "2073c6272728ed8d5844e9f92a9f73941efd9ca09909bbaf2b3ea29cc52b0c4c";
		private const string CALLBACK_URL = "http://localhost/oauth_callback";

		[Test]
		public void Constructor_NullParameter_ThrowsArgumentNullException()
		{
			Assert.Throws<ArgumentNullException>(() => new OAuth1TokenRequest(null, CONSUMER_SECRET, CALLBACK_URL));
			Assert.Throws<ArgumentNullException>(() => new OAuth1TokenRequest(CONSUMER_KEY, null, CALLBACK_URL));
			Assert.Throws<ArgumentNullException>(() => new OAuth1TokenRequest(CONSUMER_KEY, CONSUMER_SECRET, null));
		}

		[Test]
		public void Constructor_EmptyParameter_ThrowsArgumentException()
		{
			Assert.Throws<ArgumentException>(() => new OAuth1TokenRequest(string.Empty, CONSUMER_SECRET, CALLBACK_URL));
			Assert.Throws<ArgumentException>(() => new OAuth1TokenRequest(CONSUMER_KEY, string.Empty, CALLBACK_URL));
			Assert.Throws<ArgumentException>(() => new OAuth1TokenRequest(CONSUMER_KEY, CONSUMER_SECRET, string.Empty));
		}
	}
}
