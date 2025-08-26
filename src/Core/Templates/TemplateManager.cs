namespace Microsoft.ExtractorSuite.Core.Templates
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;


    public class TemplateManager

    {

        private readonly string _templatesPath;


beg

        public TemplateManager(string? templatesPath = null)
        {

            _templatesPath = templatesPath ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Templates");


        }


        public Dictionary<string, object> LoadTemplate(string templateName)
        {

            var templateFile = Path.Combine(_templatesPath, $"{templateName}.json");


            if (!File.Exists(templateFile))
            {
                throw new FileNotFoundException($"Template file not found: {templateFile}");
            }

            var json = File.ReadAllText(templateFile);
            return JsonConvert.DeserializeObject<Dictionary<string, object>>(json)
                ?? throw new InvalidOperationException($"Failed to deserialize template: {templateName}");

        }


        public IEnumerable<string> GetAvailableTemplates()
        {

            if (!Directory.Exists(_templatesPath))
            {
                return Enumerable.Empty<string>();
            }



            return Directory.GetFiles(_templatesPath, "*.json")
                .Select(Path.GetFileNameWithoutExtension)
                .Where(name => !string.IsNullOrEmpty(name) && !name.EndsWith(".schema", StringComparison.OrdinalIgnoreCase))
                .Cast<string>();


        }


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

        }


        public void SaveTemplate(string templateName, Dictionary<string, object> template)
        {

            var templateFile = Path.Combine(_templatesPath, $"{templateName}.json");

            var json = JsonConvert.SerializeObject(template, Formatting.Indented);
            File.WriteAllText(templateFile, json);
        }
    }
}
