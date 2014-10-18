﻿using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;

namespace OAuthSharp
{
    public abstract class RequestParameters
    {
        static readonly ConcurrentDictionary<Type, List<PropertyParameter>> _propertiesMap =
            new ConcurrentDictionary<Type, List<PropertyParameter>>();

        public IDictionary<string, string> ToParametersDictionary()
        {
            var map = _propertiesMap.GetOrAdd(GetType(), GetPropertyParametersForType);
            return (from property in map
                    let value = property.GetValue(this)
                    let key = property.Key
                    where value != null
                    select new { key, value }).ToDictionary(kvp => kvp.key, kvp => kvp.value);
        }

        static List<PropertyParameter> GetPropertyParametersForType(Type type)
        {
            return type.GetProperties(BindingFlags.Instance | BindingFlags.Public)
                       .Select(p => new PropertyParameter(p))
                       .ToList();
        }

        static Func<PropertyInfo, object, string> GetValueFunc(Type propertyType)
        {
            if (typeof(IEnumerable<string>).IsAssignableFrom(propertyType))
            {
                return (prop, value) =>
                {
                    var list = ((IEnumerable<string>)value).ToArray();
                    return !list.Any() ? null : String.Join(",", list);
                };
            }

            if (propertyType == typeof(DateTimeOffset) || propertyType == typeof(DateTimeOffset?))
            {
                return (prop, value) =>
                {
                    if (value == null) 
                        return null;

                    return ((DateTimeOffset)value).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
                };
            }

            if (propertyType.IsEnum)
            {
                var enumToAttributeDictionary = Enum.GetNames(propertyType)
                    .ToDictionary(name => name, name => GetParameterAttributeValueForEnumName(propertyType, name));
                
                return (prop, value) =>
                {
                    if (value == null) return null;
                    string attributeValue;

                    return enumToAttributeDictionary.TryGetValue(value.ToString(), out attributeValue)
                        ? attributeValue ?? value.ToString().ToLowerInvariant()
                        : value.ToString().ToLowerInvariant();
                };
            }

            return (prop, value) => value != null
                ? value.ToString()
                : null;
        }

        static string GetParameterAttributeValueForEnumName(Type enumType, string name)
        {
            var member = enumType.GetMember(name).FirstOrDefault();
            if (member == null) 
                return null;

            var attribute = member.GetCustomAttributes(typeof(ParameterAttribute), false)
                                  .Cast<ParameterAttribute>()
                                  .FirstOrDefault();

            return attribute != null ? attribute.Value : null;
        }

        class PropertyParameter
        {
            readonly Func<PropertyInfo, object, string> _valueFunc;
            readonly PropertyInfo _property;

            public PropertyParameter(PropertyInfo property)
            {
                _property = property;
                Key = GetParameterKeyFromProperty(property);
                _valueFunc = GetValueFunc(property.PropertyType);
            }

            public string Key { get; private set; }

            public string GetValue(object instance)
            {
                return _valueFunc(_property, _property.GetValue(instance, null));
            }

            static string GetParameterKeyFromProperty(PropertyInfo property)
            {
                var attribute = property.GetCustomAttributes(typeof(ParameterAttribute), false)
                    .Cast<ParameterAttribute>()
                    .FirstOrDefault(attr => attr.Key != null);

                return attribute == null
                    ? property.Name.ToLowerInvariant()
                    : attribute.Key;
            }
        }
    }
}
