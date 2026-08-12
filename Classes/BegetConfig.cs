using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace VirusScan2.Classes
{
    public static class BegetConfig
    {
        private static readonly string KeyUrl = "https://virusscan.ifree.page/get_key.php";
        private static readonly string AccessPassword = "ksO7QHJLHF"; // Тот же, что в PHP

        private static string _cachedApiKey;
        private static readonly object _lock = new object();

        public static async Task<string> GetVtApiKeyAsync()
        {
            // Проверяем кэш
            lock (_lock)
            {
                if (!string.IsNullOrEmpty(_cachedApiKey))
                    return _cachedApiKey;
            }

            using (var client = new HttpClient())
            {
                string url = $"{KeyUrl}?password={AccessPassword}";
                var response = await client.GetAsync(url);

                string content = await response.Content.ReadAsStringAsync();

                // ===== ИСПРАВЛЕНИЕ: Обрезаем всё, что не является JSON =====
                // Находим первую фигурную скобку и отрезаем всё до неё
                int startIndex = content.IndexOf('{');
                if (startIndex > 0)
                {
                    content = content.Substring(startIndex);
                }
                // ===========================================================

                var data = JObject.Parse(content);
                string key = data["key"]?.ToString();

                if (string.IsNullOrEmpty(key))
                    throw new Exception("Ключ не найден в ответе");

                lock (_lock)
                {
                    _cachedApiKey = key;
                }

                return key;
            }
        }
    }
}
