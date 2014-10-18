using System;

namespace OAuthSharp
{
    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property)]
    internal class ParameterAttribute : Attribute
    {
        public string Key { get; set; }
        public string Value { get; set; }
    }
}
