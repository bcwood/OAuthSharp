﻿using System;
using NUnit.Framework;

namespace OAuthSharp.Tests
{
	[TestFixture]
	public class OAuth1TokenRequestTests
	{
		[Test]
		public void Constructor_NullParameter_ThrowsArgumentNullException()
		{
			Assert.Throws<ArgumentNullException>(() => new OAuth1TokenRequest(null, TestData.CONSUMER_SECRET, TestData.CALLBACK_URL));
			Assert.Throws<ArgumentNullException>(() => new OAuth1TokenRequest(TestData.CONSUMER_KEY, null, TestData.CALLBACK_URL));
			Assert.Throws<ArgumentNullException>(() => new OAuth1TokenRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, null));
		}

		[Test]
		public void Constructor_EmptyParameter_ThrowsArgumentException()
		{
			Assert.Throws<ArgumentException>(() => new OAuth1TokenRequest(string.Empty, TestData.CONSUMER_SECRET, TestData.CALLBACK_URL));
			Assert.Throws<ArgumentException>(() => new OAuth1TokenRequest(TestData.CONSUMER_KEY, string.Empty, TestData.CALLBACK_URL));
			Assert.Throws<ArgumentException>(() => new OAuth1TokenRequest(TestData.CONSUMER_KEY, TestData.CONSUMER_SECRET, string.Empty));
		}
	}
}
