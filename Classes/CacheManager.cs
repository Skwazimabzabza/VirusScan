using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace VirusScan2.Classes
{
    public class CacheManager
    {
        private static readonly Dictionary<string, CacheEntry> _cache = new();
        private static readonly object _lock = new object();
        private readonly string _cacheFilePath;
        public string Cache {  get; set; }

        public CacheManager(string cache)
        {
            Cache = cache;
            _cacheFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, cache);
            LoadFromDisk();
            
        }

        private class CacheEntry
        {
            public string ResultJson { get; set; }
            public DateTime CreatedAt { get; set; }
        }

        public bool TryGet(string key, out string result)
        {
            lock (_lock)
            {
                if (_cache.TryGetValue(key, out CacheEntry entry))
                {
                    result = entry.ResultJson;
                    return true;
                }
                result = null;
                return false;
            }
        }

        public void Set(string key, string result)
        {
            lock (_lock)
            {
                _cache[key] = new CacheEntry
                {
                    ResultJson = result,
                    CreatedAt = DateTime.UtcNow
                };
                SaveToDisk();
            }
        }

        public void Cleanup(int maxAgeDays = 7, int maxEntries = 300, int maxFileSizeMB = 10)
        {
            lock (_lock)
            {
                // Удаляем записи старше N дней
                var cutoff = DateTime.UtcNow.AddDays(-maxAgeDays);
                var oldKeys = _cache
                    .Where(kvp => kvp.Value.CreatedAt < cutoff)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (var key in oldKeys)
                    _cache.Remove(key);

                // Если записей слишком много — удаляем самые старые
                if (_cache.Count > maxEntries)
                {
                    var toRemove = _cache
                        .OrderBy(kvp => kvp.Value.CreatedAt)
                        .Take(_cache.Count - maxEntries)
                        .Select(kvp => kvp.Key)
                        .ToList();

                    foreach (var key in toRemove)
                        _cache.Remove(key);
                }

                // Проверяем размер файла
                if (File.Exists(_cacheFilePath))
                {
                    var fileInfo = new FileInfo(_cacheFilePath);
                    if (fileInfo.Length > maxFileSizeMB * 1024 * 1024)
                    {
                        var entries = _cache
                            .OrderByDescending(kvp => kvp.Value.CreatedAt)
                            .Take(100)
                            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

                        _cache.Clear();
                        foreach (var kvp in entries)
                            _cache[kvp.Key] = kvp.Value;
                    }
                }

                SaveToDisk();
            }
        }

        private void LoadFromDisk()
        {
            try
            {
                if (File.Exists(_cacheFilePath))
                {
                    string json = File.ReadAllText(_cacheFilePath);
                    var loaded = JsonConvert.DeserializeObject<Dictionary<string, CacheEntry>>(json);
                    if (loaded != null)
                    {
                        lock (_lock)
                        {
                            _cache.Clear();
                            foreach (var kvp in loaded)
                                _cache[kvp.Key] = kvp.Value;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Не удалось загрузить кэш: {ex.Message}");
            }
        }

        private void SaveToDisk()
        {
            try
            {
                string json = JsonConvert.SerializeObject(_cache, Formatting.Indented);
                File.WriteAllText(_cacheFilePath, json);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Не удалось сохранить кэш: {ex.Message}");
            }
        }
    }
}