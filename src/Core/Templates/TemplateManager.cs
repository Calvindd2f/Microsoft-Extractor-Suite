namespace Microsoft.ExtractorSuite.Core.Templates
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

#pragma warning disable SA1600
    public class TemplateManager
#pragma warning restore SA1600
    {
#pragma warning disable SA1309
        private readonly string _templatesPath;
#pragma warning disable SA1600
#pragma warning restore SA1309
beg

        public TemplateManager(string? templatesPath = null)
        {
#pragma warning disable SA1101
            _templatesPath = templatesPath ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Templates");
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public Dictionary<string, object> LoadTemplate(string templateName)
        {
#pragma warning disable SA1101
            var templateFile = Path.Combine(_templatesPath, $"{templateName}.json");
#pragma warning restore SA1101

            if (!File.Exists(templateFile))
            {
                throw new FileNotFoundException($"Template file not found: {templateFile}");
            }

            var json = File.ReadAllText(templateFile);
            return JsonConvert.DeserializeObject<Dictionary<string, object>>(json)
                ?? throw new InvalidOperationException($"Failed to deserialize template: {templateName}");
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public IEnumerable<string> GetAvailableTemplates()
        {
#pragma warning disable SA1101
            if (!Directory.Exists(_templatesPath))
            {
                return Enumerable.Empty<string>();
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            return Directory.GetFiles(_templatesPath, "*.json")
                .Select(Path.GetFileNameWithoutExtension)
                .Where(name => !string.IsNullOrEmpty(name) && !name.EndsWith(".schema", StringComparison.OrdinalIgnoreCase))
                .Cast<string>();
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public bool ValidateTemplate(string templateContent)
        {
            try
            {
                JObject.Parse(templateContent);
                return true;
            }
            catch
            {
                return false;
            }
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public void SaveTemplate(string templateName, Dictionary<string, object> template)
        {
#pragma warning disable SA1101
            var templateFile = Path.Combine(_templatesPath, $"{templateName}.json");
#pragma warning restore SA1101
            var json = JsonConvert.SerializeObject(template, Formatting.Indented);
            File.WriteAllText(templateFile, json);
        }
    }
}
