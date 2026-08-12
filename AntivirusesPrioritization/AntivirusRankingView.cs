using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using VirusScan2.Control;

namespace VirusScan2.AntivirusesView
{
    public class AntivirusRankingView
    {

        // Метод для парсинга статистики
        public string ParseAnalysisStatsUrl(JObject analysisJson)
        {
            try
            {
                var stats = analysisJson["data"]?["attributes"]?["stats"];
                var results = analysisJson["data"]?["attributes"]?["results"];
                var status = analysisJson["data"]?["attributes"]?["status"];

                var tier1Engines = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "Kaspersky", "ESET", "BitDefender", "Sophos", "Trend Micro",
                    "Norton", "McAfee", "CrowdStrike", "Cisco Talos", "Mandiant",
                    "Google Safebrowsing", "Microsoft"
                };

                var tier2Engines = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "Dr.Web", "Avast", "AVG", "Palo Alto Networks", "Fortinet",
                    "alphaMountain.ai", "VirusTotal", "Avira", "ClamAV",
                    "Comodo", "F-Secure", "GData", "Ikarus"
                };

                if (stats != null && results != null)
                {
                    // 1. Собираем все антивирусы, которые обнаружили угрозу
                    var detectedThreatEngines = new List<string>();

                    foreach (var engine in results.Children())
                    {
                        var engineName = engine.First?["engine_name"]?.ToString();
                        var category = engine.First?["category"]?.ToString();

                        // Проверяем, обнаружил ли этот антивирус угрозу
                        if (category == "malicious" || category == "suspicious")
                        {
                            detectedThreatEngines.Add(engineName);


                            // 2. Проверяем, есть ли среди них Tier1 антивирусы
                            if (tier1Engines.Contains(engineName))
                            {
                                ResultMessageBox.Show($"🚨 ВЫСОКАЯ УГРОЗА! Обнаружено {engineName}",
                                              "ВНИМАНИЕ!!", null);
                                break; // Можно выйти, если нашли хотя бы один Tier1
                            }
                        }
                    }

                    // 3. Если не нашли Tier1, проверяем Tier2
                    if (!detectedThreatEngines.Any(e => tier1Engines.Contains(e)))
                    {
                        var tier2Detections = detectedThreatEngines.Where(e => tier2Engines.Contains(e)).ToList();

                        if (tier2Detections.Count >= 2)
                        {
                            ResultMessageBox.Show($"⚠️ СРЕДНИЙ РИСК.\nОбнаружено {tier2Detections.Count} антивирусами 2-го уровня",
                                          "Предупреждение", null);
                        }
                        else if (detectedThreatEngines.Count >= 5)
                        {
                            ResultMessageBox.Show($"🔶 НИЗКАЯ УГРОЗА. \nОбнаружено {detectedThreatEngines.Count} антивирусами",
                                          "Информация", null);
                        }
                        else if (detectedThreatEngines.Count > 10)
                        {
                            ResultMessageBox.Show($"⚠️ СРЕДНИЙ РИСК.\nОбнаружено {detectedThreatEngines.Count} антивирусами 1-го уровня",
                                          "Предупреждение", null);
                        }
                        else if (detectedThreatEngines.Any())
                        {
                            ResultMessageBox.Show($"🟡 ОЧЕНЬ НИЗКАЯ УГРОЗА.\nОбнаружено {detectedThreatEngines.Count} антивирусами",
                                          "Информация", null);
                        }
                        else
                        {
                            ResultMessageBox.Show("✅ БЕЗОПАСНО. Угроз не обнаружено",
                                          "Ура", null);
                        }
                    }

                    return $"Статус: {status}\n" +
                           $"Безопасные: {stats["harmless"]}\n" +
                           $"Вредоносные: {stats["malicious"]}\n" +
                           $"Подозрительные: {stats["suspicious"]}";
                }



                return "Данные анализа еще не готовы. Попробуйте позже.";
            }
            catch
            {
                return "Не удалось распарсить результаты";
            }
        }

        public string ParseAnalysisStatsFile(JObject analysisJson)
        {
            try
            {
                var stats = analysisJson["data"]?["attributes"]?["stats"];
                var results = analysisJson["data"]?["attributes"]?["results"];
                var status = analysisJson["data"]?["attributes"]?["status"];

                var tier1Engines = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "Kaspersky", "ESET", "BitDefender", "Sophos", "Trend Micro", "McAfee",
                    "CrowdStrike", "Microsoft", "Symantec", "SentinelOne", "Palo Alto Networks",    
                    "F-Secure", "Avast", "GData", "Panda Security", "Cylance", "Elastic", 
                    "DeepInstinct", "Cisco Talos", "Mandiant", "Norton",                 
                };

                var tier2Engines = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "Dr.Web", "AVG", "Avira",        
                    "ClamAV", "Comodo", "Ikarus", "AhnLab-V3", "Arcabit", "Tencent",
                    "Alibaba", "Webroot", "VIPRE", "Cynet", "NANO-Antivirus", "SUPERAntiSpyware",
                    "Trapmine", "APEX", "Zillya", "Jiangmin", "Kingsoft", "Xcitium",
                    "ViRobot", "ZoneAlarm", "Varist", "VBA32", "TACHYON", "Zoner",
                    "TrellixENS", "huorong", "MaxSecure", "AlphaSOC", "PrecisionSec", "SafeToOpen", 
                    "GreyNoise", "Cluster25", "ArcSight Threat Intelligence", "Hunt.io Intelligence", "AutoShun", "PREBYTES",
                    "Sangfor", "GreenSnow", "URLQuery", "DNS8", "Viettel Threat Intelligence", "Forcepoint ThreatSeeker",
                    "SCUMWARE.org", "Criminal IP", "Palo Alto Networks", "Fortinet", "alphaMountain.ai", "VirusTotal",
                };

                if (stats != null && results != null)
                {
                    // 1. Собираем все антивирусы, которые обнаружили угрозу
                    var detectedThreatEngines = new List<string>();

                    foreach (var engine in results.Children())
                    {
                        var engineName = engine.First?["engine_name"]?.ToString();
                        var category = engine.First?["category"]?.ToString();

                        // Проверяем, обнаружил ли этот антивирус угрозу
                        if (category == "malicious" || category == "suspicious")
                        {
                            detectedThreatEngines.Add(engineName);


                            // 2. Проверяем, есть ли среди них Tier1 антивирусы
                            if (tier1Engines.Contains(engineName))
                            {
                                //MessageBox.Show($"🚨 ВЫСОКАЯ УГРОЗА! Обнаружено {engineName}",
                                //              "ВНИМАНИЕ!!", MessageBoxButton.OK, MessageBoxImage.Error);
                                ResultMessageBox.Show($"🚨 ВЫСОКАЯ УГРОЗА! Обнаружено {engineName}",
                                              "ВНИМАНИЕ!!", null);
                                break; // Можно выйти, если нашли хотя бы один Tier1
                            }
                        }
                        
                    }

                    // 3. Если не нашли Tier1, проверяем Tier2
                    if (!detectedThreatEngines.Any(e => tier1Engines.Contains(e)))
                    {
                        var tier2Detections = detectedThreatEngines.Where(e => tier2Engines.Contains(e)).ToList();

                        if (tier2Detections.Count >= 2)
                        {
                            //MessageBox.Show($"⚠️ СРЕДНИЙ РИСК. Обнаружено {tier2Detections.Count} антивирусами 2-го уровня",
                            //              "Предупреждение", MessageBoxButton.OK, MessageBoxImage.Warning);
                            ResultMessageBox.Show($"⚠️ СРЕДНИЙ РИСК.\nОбнаружено {tier2Detections.Count} антивирусами 2-го уровня",
                                          "Предупреждение", null);
                        }
                        else if (detectedThreatEngines.Count >= 5)
                        {
                            //MessageBox.Show($"🔶 НИЗКАЯ УГРОЗА. Обнаружено {detectedThreatEngines.Count} антивирусами",
                            //              "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
                            ResultMessageBox.Show($"🔶 НИЗКАЯ УГРОЗА.\nОбнаружено {detectedThreatEngines.Count} антивирусами",
                                          "Информация", null);
                        }
                        else if (detectedThreatEngines.Count > 10)
                        {
                            //MessageBox.Show($"⚠️ СРЕДНИЙ РИСК. Обнаружено {detectedThreatEngines.Count} антивирусами 1-го уровня",
                            //              "Предупреждение", MessageBoxButton.OK, MessageBoxImage.Warning);
                            ResultMessageBox.Show($"⚠️ СРЕДНИЙ РИСК.\nОбнаружено {detectedThreatEngines.Count} антивирусами 1-го уровня",
                                          "Предупреждение", null);
                        }
                        else if (detectedThreatEngines.Any())
                        {
                            //MessageBox.Show($"🟡 ОЧЕНЬ НИЗКАЯ УГРОЗА. Обнаружено {detectedThreatEngines.Count} антивирусами",
                            //              "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
                            ResultMessageBox.Show($"🟡 ОЧЕНЬ НИЗКАЯ УГРОЗА.\nОбнаружено {detectedThreatEngines.Count} антивирусами",
                                          "Информация", null);
                        }
                        else
                        {
                            //MessageBox.Show("✅ БЕЗОПАСНО. Угроз не обнаружено",
                            //              "Ура", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                            ResultMessageBox.Show("✅ БЕЗОПАСНО. Угроз не обнаружено",
                                          "Ура", null);
                        }
                    }

                    return $"Статус: {status}\n" +
                           $"Безопасные: {stats["harmless"]}\n" +
                           $"Вредоносные: {stats["malicious"]}\n" +
                           $"Подозрительные: {stats["suspicious"]}";
                }


                return "Данные анализа еще не готовы. Попробуйте позже.";
            }
            catch
            {
                return "Не удалось распарсить результаты";
            }
        }


    }
}
