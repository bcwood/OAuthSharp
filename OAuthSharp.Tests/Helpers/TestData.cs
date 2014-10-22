namespace OAuthSharp.Tests
{
	public static class TestData
	{
		public const string CONSUMER_KEY = "91863bdb08a340af84f6f99b2c03f72c";
		public const string CONSUMER_SECRET = "2073c6272728ed8d5844e9f92a9f73941efd9ca09909bbaf2b3ea29cc52b0c4c";

		public const string APPLICATION_NAME = "OAuthSharp";
		public const string CALLBACK_URL = "http://localhost/oauth_callback";
		public const string CALLBACK_URL_OUT_OF_BAND = "oob";
		
		public const string OAUTH_URL_GET_REQUEST_TOKEN = "https://trello.com/1/OAuthGetRequestToken";
		public const string OAUTH_URL_AUTHORIZE_TOKEN = "https://trello.com/1/OAuthAuthorizeToken";
		public const string OAUTH_URL_GET_ACCESS_TOKEN = "https://trello.com/1/OAuthGetAccessToken";
	}
}
