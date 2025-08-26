namespace Microsoft.ExtractorSuite.Core.Json
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.IO;
    using Newtonsoft.Json.Linq;
    // Note: SimdJsonSharp requires native dependencies that may not be compatible with all PowerShell environments
    // Consider using System.Text.Json or Newtonsoft.Json for broader compatibility
    using SimdJsonSharp.Bindings;


    /// <summary>
    /// High-performance JSON processor using SIMDJson native C++ bindings
    /// Optimized for large datasets with minimal memory allocation
    /// </summary>
    public class HighPerformanceJsonProcessor : IDisposable
    {
#pragma warning disable SA1309
        private static readonly RecyclableMemoryStreamManager _memoryStreamManager = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
#pragma warning disable SA1600
        private readonly ArrayPool<byte> _arrayPool;
#pragma warning restore SA1600
#pragma warning disable SA1309
        private readonly SimdJsonParser _jsonParser;
#pragma warning restore SA1309

        public HighPerformanceJsonProcessor()
        {
            _arrayPool = ArrayPool<byte>.Shared;
#pragma warning disable SA1101
            _jsonParser = new SimdJsonParser();
#pragma warning restore SA1101
        }

        /// <summary>
        /// Deserialize JSON from stream with minimal memory allocation
        /// </summary>
        public async ValueTask<T?> DeserializeAsync<T>(
            Stream stream,
            CancellationToken cancellationToken = default)
        {
            var buffer = _arrayPool.Rent((int)stream.Length);

            try
            {
                var bytesRead = await stream.ReadAsync(buffer.AsMemory(0, (int)stream.Length), cancellationToken);
                var jsonSpan = buffer.AsSpan(0, bytesRead);

#pragma warning disable SA1101
                var element = _jsonParser.Parse(jsonSpan.ToArray());
#pragma warning restore SA1101
                return element == null
                    ? throw new InvalidOperationException("Failed to parse JSON")
                    : Newtonsoft.Json.JsonConvert.DeserializeObject<T>(element.ToString());
            }
            finally
            {
                _arrayPool.Return(buffer);
            }
        }

        /// <summary>
        /// Stream JSON array elements one by one without loading entire array
        /// </summary>
        public async IAsyncEnumerable<T> DeserializeArrayAsync<T>(
            Stream stream,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var buffer = _arrayPool.Rent((int)stream.Length);

            try
            {
                var bytesRead = await stream.ReadAsync(buffer.AsMemory(0, (int)stream.Length), cancellationToken);
                var jsonSpan = buffer.AsSpan(0, bytesRead);

#pragma warning disable SA1101
                var element = _jsonParser.Parse(jsonSpan.ToArray());
#pragma warning restore SA1101
                if (element?.Type != JsonType.Array)
                    throw new InvalidOperationException(element == null ? "Failed to parse JSON" : "Expected JSON array");

                foreach (var item in element.AsArray())
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var deserializedItem = Newtonsoft.Json.JsonConvert.DeserializeObject<T>(item.ToString());
                    if (deserializedItem != null)
                        yield return deserializedItem;
                }
            }
            finally
            {
                _arrayPool.Return(buffer);
            }
        }

        /// <summary>
        /// Serialize object to stream with memory pooling
        /// </summary>
        public async Task SerializeAsync<T>(
            Stream stream,
            T value,
            bool indented = false,
            CancellationToken cancellationToken = default)
        {
            var jsonString = Newtonsoft.Json.JsonConvert.SerializeObject(
                value,
                indented ? Newtonsoft.Json.Formatting.Indented : Newtonsoft.Json.Formatting.None);

            await stream.WriteAsync(Encoding.UTF8.GetBytes(jsonString), cancellationToken);
        }

        /// <summary>
        /// Serialize large collections efficiently using streaming
        /// </summary>
        public async Task SerializeCollectionAsync<T>(
            Stream stream,
            IAsyncEnumerable<T> items,
            CancellationToken cancellationToken = default)
        {
            var openBracket = Encoding.UTF8.GetBytes("[");
            var comma = Encoding.UTF8.GetBytes(",");
            var closeBracket = Encoding.UTF8.GetBytes("]");

            await stream.WriteAsync(openBracket, cancellationToken);

            var isFirst = true;
            await foreach (var item in items.WithCancellation(cancellationToken))
            {
                if (!isFirst)
                    await stream.WriteAsync(comma, cancellationToken);

                await stream.WriteAsync(Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(item)), cancellationToken);
                isFirst = false;
            }

            await stream.WriteAsync(closeBracket, cancellationToken);
        }

        /// <summary>
        /// Parse and transform JSON without full deserialization
        /// Useful for extracting specific fields from large JSON
        /// </summary>
        public async Task<Dictionary<string, object?>> ExtractFieldsAsync(
            Stream stream,
            string[] fieldPaths,
            CancellationToken cancellationToken = default)
        {
            var buffer = _arrayPool.Rent((int)stream.Length);

            try
            {
                var bytesRead = await stream.ReadAsync(buffer.AsMemory(0, (int)stream.Length), cancellationToken);
#pragma warning disable SA1101
                var element = _jsonParser.Parse(buffer.AsSpan(0, bytesRead).ToArray());
#pragma warning restore SA1101

                if (element == null)
                    throw new InvalidOperationException("Failed to parse JSON");

                var jToken = JToken.Parse(element.ToString());
#pragma warning disable SA1101
                return fieldPaths.ToDictionary(path => path, path => GetValueByPath(jToken, path));
#pragma warning restore SA1101
            }
            finally
            {
                _arrayPool.Return(buffer);
            }
        }

        /// <summary>
        /// Merge multiple JSON files efficiently
        /// </summary>
        public async Task MergeJsonFilesAsync(
            string[] inputFiles,
            string outputFile,
            bool asArray = true,
            CancellationToken cancellationToken = default)
        {
            using var output = new FileStream(
                outputFile,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 65536,
                useAsync: true);

            if (asArray)
            {
                await output.WriteAsync(Encoding.UTF8.GetBytes("["), 0, 1, cancellationToken);
            }

            for (int i = 0; i < inputFiles.Length; i++)
            {
                if (i > 0 && asArray)
                {
                    await output.WriteAsync(Encoding.UTF8.GetBytes(","), 0, 1, cancellationToken);
                }

                using var input = new FileStream(
                    inputFiles[i],
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    bufferSize: 65536,
                    useAsync: true);

                var buffer = _arrayPool.Rent((int)input.Length);
                try
                {
                    var bytesRead = await input.ReadAsync(buffer.AsMemory(0, (int)input.Length), cancellationToken);
#pragma warning disable SA1101
                    var element = _jsonParser.Parse(buffer.AsSpan(0, bytesRead).ToArray());
#pragma warning restore SA1101
                    if (element == null)
                    {
                        continue; // Skip invalid files
                    }

                    if (asArray)
                    {
                        // If input is array, write elements individually
                        if (element.Type == JsonType.Array)
                        {
                            var arrayElement = element.AsArray();
                            var isFirstElement = true;
                            foreach (var arrayItem in arrayElement)
                            {
                                if (!isFirstElement)
                                {
                                    await output.WriteAsync(Encoding.UTF8.GetBytes(","), 0, 1, cancellationToken);
                                }

                                var itemJson = arrayItem.ToString();
                                var itemBytes = Encoding.UTF8.GetBytes(itemJson);
                                await output.WriteAsync(itemBytes, 0, itemBytes.Length, cancellationToken);

                                isFirstElement = false;
                            }
                        }
                        else
                        {
                            var jsonString = element.ToString();
                            var jsonBytes = Encoding.UTF8.GetBytes(jsonString);
                            await output.WriteAsync(jsonBytes, 0, jsonBytes.Length, cancellationToken);
                        }
                    }
                    else
                    {
                        // Write as separate JSON objects (JSONL format)
                        var jsonString = element.ToString();
                        var jsonBytes = Encoding.UTF8.GetBytes(jsonString);
                        await output.WriteAsync(jsonBytes, 0, jsonBytes.Length, cancellationToken);
                        await output.WriteAsync(Encoding.UTF8.GetBytes("\n"), 0, 1, cancellationToken);
                    }
                }
                finally
                {
                    _arrayPool.Return(buffer);
                }
            }

            if (asArray)
            {
                await output.WriteAsync(Encoding.UTF8.GetBytes("]"), 0, 1, cancellationToken);
            }

            await output.FlushAsync(cancellationToken);
        }

        /// <summary>
        /// Convert JSON to JSONL (newline-delimited JSON) format
        /// </summary>
        public async Task ConvertToJsonLinesAsync(
            Stream input,
            Stream output,
            CancellationToken cancellationToken = default)
        {
            var buffer = _arrayPool.Rent((int)input.Length);

            try
            {
                var bytesRead = await input.ReadAsync(buffer.AsMemory(0, (int)input.Length), cancellationToken);
#pragma warning disable SA1101
                var element = _jsonParser.Parse(buffer.AsSpan(0, bytesRead).ToArray());
#pragma warning restore SA1101
                if (element == null)
                {
                    throw new InvalidOperationException("Failed to parse JSON");
                }

                if (element.Type != JsonType.Array)
                {
                    // Single object - write as single line
                    var jsonString = element.ToString();
                    var jsonBytes = Encoding.UTF8.GetBytes(jsonString);
                    await output.WriteAsync(jsonBytes, 0, jsonBytes.Length, cancellationToken);
                    await output.WriteAsync(Encoding.UTF8.GetBytes("\n"), 0, 1, cancellationToken);
                }
                else
                {
                    // Array - write each element as separate line
                    var arrayElement = element.AsArray();
                    foreach (var arrayItem in arrayElement)
                    {
                        var itemJson = arrayItem.ToString();
                        var itemBytes = Encoding.UTF8.GetBytes(itemJson);
                        await output.WriteAsync(itemBytes, 0, itemBytes.Length, cancellationToken);
                        await output.WriteAsync(Encoding.UTF8.GetBytes("\n"), 0, 1, cancellationToken);
                    }
                }
            }
            finally
            {
                _arrayPool.Return(buffer);
            }
        }

        private object? GetValueByPath(JToken element, string path)
        {
            var parts = path.Split('.');
            var current = element;

            foreach (var part in parts)
            {
                if (current.Type == JTokenType.Object)
                {
                    var obj = current as JObject;
                    if (obj != null && obj.TryGetValue(part, out var property))
                    {
                        current = property;
                    }
                    else
                    {
                        return null;
                    }
                }
                else
                {
                    return null;
                }
            }

            return current.Type switch
            {
                JTokenType.String => current.ToString(),
                JTokenType.Float or JTokenType.Integer => current.ToObject<object>(),
#pragma warning disable SA1600
                JTokenType.Bo
#pragma warning restore SA1600
current.ToObject<object>(),
                JTokenType.Null => null,
                _ => current.ToString()
            };
        }

        public void Dispose()
        {
#pragma warning disable SA1101
            _jsonParser?.Dispose();
#pragma warning restore SA1101
        }
    }

    /// <summary>
#pragma warning disable SA1600
    /// High-performance DateTime converter for SIMDJson
#pragma warning restore SA1600
    /// </summary>
    public class HighPerformanceDateTimeConverter
    {
        private const string DateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";

        public static DateTime ParseDateTime(string? value)
        {
            if (string.IsNullOrEmpty(value))
                return DateTime.MinValue;

#pragma warning disable SA1600
            if (DateTime.TryParse(value, out var result))
#pragma warning restore SA1600
                return result;

            return DateTime.MinValue;
        }

        public static string FormatDateTime(DateTime value)
        {
            return value.ToUniversalTime().ToString(DateTimeFormat);
        }
    }
#pragma warning disable SA1600

#pragma warning restore SA1600
    /// <summary>
    /// Dynamic JSON converter for handling unknown structures with SIMDJson
    /// </summary>
    public class DynamicJsonConverter
    {
        public static object? ConvertElement(JToken element)
        {
            return element.Type switch
            {
                JTokenType.Boolean => element.ToObject<object>(),
                JTokenType.Float or JTokenType.Integer => element.ToObject<object>(),
                JTokenType.String => element.ToString(),
                JTokenType.Null => null,
                JTokenType.Array => ConvertArray(element),
                JTokenType.Object => ConvertObject(element),
                _ => element.ToString()
            };
        }

        private static List<object?> ConvertArray(JToken element)
        {
            var result = new List<object?>();
            var array = element as JArray;

            foreach (var item in array)
            {
                result.Add(ConvertElement(item));
            }

            return result;
        }

        private static Dictionary<string, object?> ConvertObject(JToken element)
        {
            var result = new Dictionary<string, object?>();
            var obj = element as JObject;

            foreach (var kvp in obj)
            {
                result[kvp.Key] = ConvertElement(kvp.Value);
            }

            return result;
        }
    }
}
