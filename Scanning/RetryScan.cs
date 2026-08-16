using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Polly;
using Polly.Retry;
using SharpCompress.Common;
using Supabase;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Shapes;
using VirusScan2.Classes;
using VirusScan2.Classes.SaveToFiles;
using VirusScan2.DataBase;

namespace VirusScan2.Scanning
{
    public class RetryScan
    {
        private Scan scan;
        private static Dictionary<string, string> _localCache = new();
        private static readonly object _cacheLock = new object();
        private CacheManager _cacheManager;
        private AsyncRetryPolicy<string> CreateRetryPolicy(int seconds, int count)
        {
            return Policy<string>
                .Handle<Exception>()
                .OrResult(result => IsAnalysisIncomplete(result))
                .WaitAndRetryAsync(
                    retryCount: count,
                    sleepDurationProvider: retryAttempt =>
                        TimeSpan.FromSeconds(Math.Min(Math.Pow(seconds, retryAttempt), 30)), // Экспоненциальная задержка
                    onRetry: (outcome, timespan, retryCount, context) =>
                    {
                        string status = GetStatusFromResponse(outcome.Result);
                        Debug.WriteLine($"Попытка {retryCount}. Статус: {status}. Жду {timespan.TotalSeconds} сек");
                    });
        }

        private bool IsAnalysisIncomplete(string apiResponse)
        {
            try
            {
                if (string.IsNullOrEmpty(apiResponse))
                    return true;

                var json = JObject.Parse(apiResponse);
                string status = json["data"]?["attributes"]?["status"]?.ToString();

                // Возвращаем true если анализ НЕ завершён
                return status != "completed";
            }
            catch
            {
                return true; // При ошибке парсинга считаем неполным
            }
        }

        private string GetStatusFromResponse(string response)
        {
            try
            {
                var json = JObject.Parse(response);
                return json["data"]?["attributes"]?["status"]?.ToString() ?? "unknown";
            }
            catch
            {
                return "invalid_json";
            }
        }

        public async Task<string> ScanWithRetryPolicyUrl(string url, string baseUrl, string header)
        {
            scan = new();

            string scanResult = await scan.ScanAsync(url, baseUrl, header);
            var jsonResponse = JObject.Parse(scanResult);
            string analysisId = jsonResponse["data"]?["id"]?.ToString();

            if (string.IsNullOrEmpty(analysisId))
                throw new Exception("Не удалось получить ID анализа");

            for (int attempt = 0; attempt < 50; attempt++)
            {
                string analysisResult = await scan.GetAnalysisResultsAsync(analysisId, baseUrl);
                var analysisJson = JObject.Parse(analysisResult);
                string status = analysisJson["data"]?["attributes"]?["status"]?.ToString();
                var stats = analysisJson["data"]?["attributes"]?["stats"];

                //Последняя часть условия из-за того что VT может вернуть статус "in-progress" даже когда анализ завершён(только с ссылками такое происходит)
                if (status == "completed" || (status == "in-progress" && ScanResult.IsMalicious(analysisJson)) || (status == "in-progress" && ScanResult.IsHarmless(analysisJson)))
                {
                    MessageBox.Show($"УСПЕХ! Возвращаю результат:\n Cтатус: {status}");
                    return analysisResult;
                }

                MessageBox.Show($"Попытка {attempt + 1}. Статус: {status}. Жду...");
                await Task.Delay(1000 * (attempt + 1));
            }

            throw new Exception("Анализ не завершился за отведённое время");
        }

        private async Task<string> WaitForAnalysis(string analysisId, string baseUrl)
        {
            Scan scan = new();
            for (int attempt = 0; attempt < 10; attempt++)
            {
                string result = await scan.GetAnalysisResultsAsync(analysisId, baseUrl);
                var json = JObject.Parse(result);
                string status = json["data"]?["attributes"]?["status"]?.ToString();

                if (status == "completed")
                {
                    // Обновляем статус в БД
                    var response = await DBClient.Instance.From<FilesDB>()
                        .Where(s => s.AnalysisId == analysisId)
                        .Get();

                    var existing = response.Models.FirstOrDefault();
                    if (existing != null)
                    {
                        existing.Status = "completed";
                        existing.ResultJson = result;
                        await DBClient.Instance.From<FilesDB>().Update(existing);
                    }

                    return result;
                }

                // Ждём перед следующей попыткой (экспоненциальная задержка)
                await Task.Delay(1000 * (attempt + 1));
            }

            throw new Exception("Анализ не завершился за отведённое время");
        }

        public async Task<bool> IsDbAvailable()
        {
            try
            {
                var response = await DBClient.Instance.From<FilesDB>().Limit(1).Get();
                return response.Models != null;
            }
            catch
            {
                return false;
            }
        }

        public async Task<JObject> GetCachedOrScanFile(string filePath, string baseUrl, string jsonResultFile, string fileName)
        {
            string hash = ComputeSha256(filePath);
            _cacheManager = new CacheManager("filesCache.json");

            //1. Проверяем локальный кэш в памяти
            if (_cacheManager.TryGet(hash, out string cachedResult))
            {
                Debug.WriteLine($"Кэш: результат для {hash} найден.");
                return JObject.Parse(cachedResult);
            }

            //2. Загружаем кэш с диска (если в памяти нет)
            

            //3. Проверяем БД
            try
            {
                var response = await DBClient.Instance.From<FilesDB>()
                    .Where(s => s.Hash == hash)
                    .Get();

                var existing = response.Models.FirstOrDefault();

                if (existing != null && existing.Status == "completed")
                {
                    lock (_cacheLock)
                    {
                        _localCache[hash] = existing.ResultJson;
                        SaveCacheToDisk(); // Сохраняем в диск для будущих запусков
                    }
                    return JObject.Parse(existing.ResultJson);
                }

                if (existing != null && existing.Status != "completed")
                {
                    string result = await WaitForAnalysis(existing.AnalysisId, baseUrl);
                    lock (_cacheLock)
                    {
                        _localCache[hash] = result;
                        SaveCacheToDisk();
                    }
                    return JObject.Parse(result);
                }
            }
            catch (Exception ex) when (ex is HttpRequestException ||
                                       ex is TaskCanceledException ||
                                       ex.Message.Contains("SSL") ||
                                       ex.Message.Contains("network") ||
                                       ex.Message.Contains("timeout"))
            {
                MessageBox.Show("База данных временно недоступна. Сканирование будет выполнено напрямую через VirusTotal.");
                Debug.WriteLine($"Ошибка БД: {ex.Message}");
            }

            //4. БД недоступна или записи нет — отправляем в VirusTotal
            string scanResult = await ScanWithRetryPolicyFile(filePath, baseUrl);
            var analysisJson = JObject.Parse(scanResult);

            //5. Сохраняем в локальный кэш и на диск
            _cacheManager.Set(hash, scanResult);

            //6. Пытаемся сохранить в БД
            try
            {
                var scan = new FilesDB
                {
                    FileName = fileName,
                    Hash = hash,
                    AnalysisId = analysisJson["data"]?["id"]?.ToString(),
                    Status = "completed",
                    ResultJson = scanResult,
                    ScanDate = DateTime.UtcNow
                };
                await DBClient.Instance.From<FilesDB>().Insert(scan);
                await JSONSave.Save(analysisJson, jsonResultFile);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Не удалось сохранить в БД: {ex.Message}");
            }

            return analysisJson;
        }

        //Вспомогательные методы

        private void SaveCacheToDisk()
        {
            try
            {
                string cacheFile = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cache.json");
                string json = JsonConvert.SerializeObject(_localCache, Formatting.Indented);
                int maxLinesLimit = 50; // Ваш лимит строк

                var lines = File.ReadAllLines(cacheFile).ToList();

                // Проверяем лимит (учитываем +2 строки на открывающую и закрывающую скобки)
                if (lines.Count > maxLinesLimit && lines.Count > 3)
                {
                    // Удаляем САМУЮ ПЕРВУЮ ЗАПИСЬ (она идет сразу после скобки '{', то есть на индексе 1)
                    lines.RemoveAt(1);
                }

                File.WriteAllLines(cacheFile, lines);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Не удалось сохранить кэш на диск: {ex.Message}");
            }
        }

        public async Task<JObject> GetCachedOrScanUrl(string url, string baseUrl, string header)
        {
            string urlHash = NormalizeAndHashUrl(url);
            _cacheManager = new CacheManager("urlsCache.json");

            //1. Проверяем кэш
            if (_cacheManager.TryGet(urlHash, out string cachedResult))
            {
                Debug.WriteLine($"Кэш: результат для URL {url} найден.");
                return JObject.Parse(cachedResult);
            }

            //2. Проверяем БД
            try
            {
                var response = await DBClient.Instance.From<URLsDB>()
                    .Where(s => s.UrlHash == urlHash)
                    .Get();

                var existing = response.Models.FirstOrDefault();

                if (existing != null)
                {
                    if (existing.Status == "completed")
                    {
                        // Сохраняем в кэш и возвращаем
                        _cacheManager.Set(urlHash, existing.ResultJson);
                        return JObject.Parse(existing.ResultJson);
                    }

                    if (existing.Status == "in-progress" && ScanResult.IsMalicious(JObject.Parse(existing.ResultJson)))
                    {
                        _cacheManager.Set(urlHash, existing.ResultJson);
                        return JObject.Parse(existing.ResultJson);
                    }
                }

                if (existing != null)
                {
                    if (existing.Status != "completed")
                    {
                        string result = await WaitForAnalysis(existing.AnalysisId, baseUrl);
                        _cacheManager.Set(urlHash, result);
                        return JObject.Parse(result);
                    }

                    if (existing.Status != "in-progress" && ScanResult.IsHarmless(JObject.Parse(existing.ResultJson)))
                    {
                        string result = await WaitForAnalysis(existing.AnalysisId, baseUrl);
                        _cacheManager.Set(urlHash, result);
                        return JObject.Parse(result);
                    }
                }
            }
            catch (Exception ex) when (ex is HttpRequestException ||
                                       ex is TaskCanceledException ||
                                       ex.Message.Contains("SSL") ||
                                       ex.Message.Contains("network") ||
                                       ex.Message.Contains("timeout"))
            {
                MessageBox.Show("База данных временно недоступна. Сканирование будет выполнено напрямую через VirusTotal.");
                Debug.WriteLine($"Ошибка БД: {ex.Message}");
            }

            //3. БД недоступна или записи нет — отправляем в VirusTotal
            string scanResult = await ScanWithRetryPolicyUrl(url, baseUrl, header);
            var analysisJson = JObject.Parse(scanResult);

            //4. Сохраняем в кэш
            _cacheManager.Set(urlHash, scanResult);

            //5. Пытаемся сохранить в БД
            try
            {
                string status = analysisJson["data"]?["attributes"]?["status"]?.ToString();
                var scan = new URLsDB
                {
                    Url = url,
                    UrlHash = urlHash,
                    AnalysisId = analysisJson["data"]?["id"]?.ToString(),
                    Status = status == "completed" ? "completed" : "in-progress",
                    ResultJson = scanResult,
                    ScanDate = DateTime.UtcNow
                };

                await DBClient.Instance.From<URLsDB>().Insert(scan);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Не удалось сохранить в БД: {ex.Message}");
            }

            return analysisJson;
        }

        public async Task<string> ScanWithRetryPolicyFile(string filePath, string baseUrl)
        {
            var retryPolicy = CreateRetryPolicy(20, 30);
            Scan scan = new Scan();


            if (!SizeLimiter.Limit(filePath, 32))
            {
                string largeFile = await scan.GetLargeFilesUrlAsync();
                string largeScanResult = await scan.ScanAsync(largeFile, filePath);
                var largeJsonResponse = JObject.Parse(largeScanResult);
                

                return await retryPolicy.ExecuteAsync(async () =>
                {
                    // 2. Извлекаем ID анализа
                    string largeAnalysisId = largeJsonResponse["data"]?["id"]?.ToString();
                    if (string.IsNullOrEmpty(largeAnalysisId))
                        throw new Exception("Не удалось получить ID анализа");
                    // 3. Получаем результаты повторно пока статус != completed
                    string largeAnalysisResult = await scan.GetAnalysisResultsAsync(largeAnalysisId, baseUrl);
                    var largeAnalysisJson = JObject.Parse(largeAnalysisResult);
                    string largeStatus = largeAnalysisJson["data"]?["attributes"]?["status"]?.ToString();

                    // 4. Если анализ не завершён — бросаем исключение (повтор)
                    if (largeStatus != "completed")
                        throw new Exception($"Анализ не завершён. Статус: {largeStatus}");

                    return largeAnalysisResult;
                });
            }

            else
            {
                string scanResult = await scan.ScanAsync("https://www.virustotal.com/api/v3/files", filePath);
                var jsonResponse = JObject.Parse(scanResult);
                return await retryPolicy.ExecuteAsync(async () =>
                {
                    string analysisId = jsonResponse["data"]?["id"]?.ToString();
                    if (string.IsNullOrEmpty(analysisId))
                        throw new Exception("Не удалось получить ID анализа");

                    // 3. Получаем результаты повторно пока статус != completed

                    string analysisResult = await scan.GetAnalysisResultsAsync(analysisId, baseUrl);
                    var analysisJson = JObject.Parse(analysisResult);
                    string status = analysisJson["data"]?["attributes"]?["status"]?.ToString();

                    //4.Если анализ не завершён — бросаем исключение(повтор)
    
                    if (status != "completed")
                        throw new Exception($"Анализ не завершён. Статус: {status}");

                    return analysisResult;
                });

            }

        }

        

        public static string NormalizeAndHashUrl(string url)
        {
            // 1. Нормализация: убрать www, лишние слеши, привести к нижнему регистру
            var uri = new Uri(url);
            string normalized = uri.Host.ToLower() + uri.PathAndQuery;

            // 2. SHA-256
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(normalized));
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }
        public string ComputeSha256(string filePath)
        {
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            using (var stream = File.OpenRead(filePath))
            {
                byte[] hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }


    }

}

