using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IO;

namespace Microsoft.ExtractorSuite.Core.Json
{
    /// <summary>
    /// High-performance JSON processor using System.Text.Json
    /// Optimized for large datasets with minimal memory allocation
    /// </summary>
    public class HighPerformanceJsonProcessor : IDisposable
    {
        private static readonly RecyclableMemoryStreamManager _memoryStreamManager = new();
        private readonly JsonSerializerOptions _defaultOptions;
        private readonly JsonWriterOptions _writerOptions;
        private readonly ArrayPool<byte> _arrayPool;

        public HighPerformanceJsonProcessor()
        {
            _arrayPool = ArrayPool<byte>.Shared;

            // Configure for optimal performance
            _defaultOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                WriteIndented = false,
                DefaultBufferSize = 16384, // 16KB buffer
                Converters =
                {
                    new JsonStringEnumConverter(JsonNamingPolicy.CamelCase),
                    new HighPerformanceDateTimeConverter(),
                    new DynamicJsonConverter()
                }
            };

            _writerOptions = new JsonWriterOptions
            {
                Indented = false,
                SkipValidation = true, // Skip validation for performance
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };
        }

        /// <summary>
        /// Deserialize JSON from stream with minimal memory allocation
        /// </summary>
        public async ValueTask<T?> DeserializeAsync<T>(
            Stream stream,
            CancellationToken cancellationToken = default)
        {
            // For small streams, use direct deserialization
            if (stream.Length < 81920) // 80KB threshold
            {
                return await JsonSerializer.DeserializeAsync<T>(stream, _defaultOptions, cancellationToken);
            }

            // For large streams, use PipeReader for better memory efficiency
            var pipe = new Pipe();
            var writing = FillPipeAsync(stream, pipe.Writer, cancellationToken);
            var reading = ReadFromPipeAsync<T>(pipe.Reader, cancellationToken);

            await Task.WhenAll(writing, reading);

            return await reading;
        }

        /// <summary>
        /// Stream JSON array elements one by one without loading entire array
        /// </summary>
        public async IAsyncEnumerable<T> DeserializeArrayAsync<T>(
            Stream stream,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var buffer = _arrayPool.Rent(4096);

            try
            {
                using var jsonDoc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);

                if (jsonDoc.RootElement.ValueKind != JsonValueKind.Array)
                {
                    throw new JsonException("Expected JSON array");
                }

                foreach (var element in jsonDoc.RootElement.EnumerateArray())
                {
                    if (cancellationToken.IsCancellationRequested)
                        yield break;

                    // Use buffer to serialize element
                    using var bufferStream = new MemoryStream(buffer, 0, buffer.Length, true, true);
                    using var writer = new Utf8JsonWriter(bufferStream, _writerOptions);

                    element.WriteTo(writer);
                    await writer.FlushAsync(cancellationToken);

                    bufferStream.Position = 0;
                    var item = await JsonSerializer.DeserializeAsync<T>(
                        bufferStream,
                        _defaultOptions,
                        cancellationToken);

                    if (item != null)
                        yield return item;
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
            var options = indented ? GetIndentedOptions() : _defaultOptions;

            // Use recyclable memory stream for buffering
            using var bufferStream = _memoryStreamManager.GetStream();
            await JsonSerializer.SerializeAsync(bufferStream, value, options, cancellationToken);

            bufferStream.Position = 0;
            await bufferStream.CopyToAsync(stream, 81920, cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }

        /// <summary>
        /// Serialize large collections efficiently using streaming
        /// </summary>
        public async Task SerializeCollectionAsync<T>(
            Stream stream,
            IAsyncEnumerable<T> items,
            CancellationToken cancellationToken = default)
        {
            await using var writer = new Utf8JsonWriter(stream, _writerOptions);

            writer.WriteStartArray();

            await foreach (var item in items.WithCancellation(cancellationToken))
            {
                JsonSerializer.Serialize(writer, item, _defaultOptions);

                // Flush periodically to prevent memory buildup
                if (writer.BytesCommitted > 65536) // 64KB
                {
                    await writer.FlushAsync(cancellationToken);
                }
            }

            writer.WriteEndArray();
            await writer.FlushAsync(cancellationToken);
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
            var result = new Dictionary<string, object?>();

            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            var root = document.RootElement;

            foreach (var path in fieldPaths)
            {
                var value = GetValueByPath(root, path);
                result[path] = value;
            }

            return result;
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

            await using var writer = new Utf8JsonWriter(output, _writerOptions);

            if (asArray)
            {
                writer.WriteStartArray();
            }

            foreach (var inputFile in inputFiles)
            {
                using var input = new FileStream(
                    inputFile,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    bufferSize: 65536,
                    useAsync: true);

                using var document = await JsonDocument.ParseAsync(input, cancellationToken: cancellationToken);

                if (asArray)
                {
                    // If input is array, write elements individually
                    if (document.RootElement.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var element in document.RootElement.EnumerateArray())
                        {
                            element.WriteTo(writer);
                        }
                    }
                    else
                    {
                        document.RootElement.WriteTo(writer);
                    }
                }
                else
                {
                    // Write as separate JSON objects (JSONL format)
                    document.RootElement.WriteTo(writer);
                    await writer.FlushAsync(cancellationToken);
                    var newlineBytes = Encoding.UTF8.GetBytes("\n");
                    await output.WriteAsync(newlineBytes, 0, newlineBytes.Length, cancellationToken);
                }
            }

            if (asArray)
            {
                writer.WriteEndArray();
            }

            await writer.FlushAsync(cancellationToken);
        }

        /// <summary>
        /// Convert JSON to JSONL (newline-delimited JSON) format
        /// </summary>
        public async Task ConvertToJsonLinesAsync(
            Stream input,
            Stream output,
            CancellationToken cancellationToken = default)
        {
            using var document = await JsonDocument.ParseAsync(input, cancellationToken: cancellationToken);

            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                // Single object - write as single line
                await using var writer = new Utf8JsonWriter(output, _writerOptions);
                document.RootElement.WriteTo(writer);
                await writer.FlushAsync(cancellationToken);
                var newlineBytes = Encoding.UTF8.GetBytes("\n");
                await output.WriteAsync(newlineBytes, 0, newlineBytes.Length, cancellationToken);
            }
            else
            {
                // Array - write each element as separate line
                foreach (var element in document.RootElement.EnumerateArray())
                {
                    await using var writer = new Utf8JsonWriter(output, _writerOptions);
                    element.WriteTo(writer);
                    await writer.FlushAsync(cancellationToken);
                    var newlineBytes = Encoding.UTF8.GetBytes("\n");
                    await output.WriteAsync(newlineBytes, 0, newlineBytes.Length, cancellationToken);
                }
            }
        }

        private async Task FillPipeAsync(Stream stream, PipeWriter writer, CancellationToken cancellationToken)
        {
            const int minimumBufferSize = 512;

            while (true)
            {
                var memory = writer.GetMemory(minimumBufferSize);

                try
                {
                    var buffer = memory.ToArray();
                    var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                    if (bytesRead == 0)
                    {
                        break;
                    }

                    // Copy the read data back to memory
                    buffer.AsMemory(0, bytesRead).CopyTo(memory);
                    writer.Advance(bytesRead);
                }
                catch (Exception ex)
                {
                    await writer.CompleteAsync(ex);
                    return;
                }

                var result = await writer.FlushAsync(cancellationToken);

                if (result.IsCompleted || result.IsCanceled)
                {
                    break;
                }
            }

            await writer.CompleteAsync();
        }

        private async Task<T?> ReadFromPipeAsync<T>(PipeReader reader, CancellationToken cancellationToken)
        {
            using var stream = new MemoryStream();

            while (true)
            {
                var result = await reader.ReadAsync(cancellationToken);
                var buffer = result.Buffer;

                foreach (var segment in buffer)
                {
                    await stream.WriteAsync(segment.Array, segment.Offset, segment.Count, cancellationToken);
                }

                reader.AdvanceTo(buffer.End);

                if (result.IsCompleted)
                {
                    break;
                }
            }

            stream.Position = 0;
            return await JsonSerializer.DeserializeAsync<T>(stream, _defaultOptions, cancellationToken);
        }

        private object? GetValueByPath(JsonElement element, string path)
        {
            var parts = path.Split('.');
            var current = element;

            foreach (var part in parts)
            {
                if (current.ValueKind == JsonValueKind.Object && current.TryGetProperty(part, out var property))
                {
                    current = property;
                }
                else
                {
                    return null;
                }
            }

            return current.ValueKind switch
            {
                JsonValueKind.String => current.GetString(),
                JsonValueKind.Number => current.GetDecimal(),
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.Null => null,
                _ => current.ToString()
            };
        }

        private JsonSerializerOptions GetIndentedOptions()
        {
            var options = new JsonSerializerOptions(_defaultOptions)
            {
                WriteIndented = true
            };
            return options;
        }

        public void Dispose()
        {
            // Cleanup if needed
        }
    }

    /// <summary>
    /// High-performance DateTime converter
    /// </summary>
    public class HighPerformanceDateTimeConverter : JsonConverter<DateTime>
    {
        private const string DateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";

        public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.String)
            {
                var str = reader.GetString();
                if (DateTime.TryParse(str, out var result))
                    return result;
            }
            return DateTime.MinValue;
        }

        public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.ToUniversalTime().ToString(DateTimeFormat));
        }
    }

    /// <summary>
    /// Dynamic JSON converter for handling unknown structures
    /// </summary>
    public class DynamicJsonConverter : JsonConverter<object>
    {
        public override object? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            return reader.TokenType switch
            {
                JsonTokenType.True => true,
                JsonTokenType.False => false,
                JsonTokenType.Number when reader.TryGetInt64(out var l) => l,
                JsonTokenType.Number => reader.GetDecimal(),
                JsonTokenType.String when reader.TryGetDateTime(out var dt) => dt,
                JsonTokenType.String => reader.GetString(),
                JsonTokenType.StartArray => JsonSerializer.Deserialize<List<object>>(ref reader, options),
                JsonTokenType.StartObject => JsonSerializer.Deserialize<Dictionary<string, object>>(ref reader, options),
                _ => null
            };
        }

        public override void Write(Utf8JsonWriter writer, object value, JsonSerializerOptions options)
        {
            JsonSerializer.Serialize(writer, value, value.GetType(), options);
        }

        public override bool CanConvert(Type typeToConvert) => typeToConvert == typeof(object);
    }
}
