using Newtonsoft.Json.Linq;
using SharpCompress.Archives;
using SharpCompress.Archives.Rar;
using SharpCompress.Common;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using VirusScan2.AntivirusesView;
using VirusScan2.Classes;
using VirusScan2.Classes.SaveToFiles;
using VirusScan2.Control;
using VirusScan2.Controls.CustomControl;
using VirusScan2.Windows;
using VirusScan2.Windows.CustomWindow;

namespace VirusScan2.Scanning
{
    public class ArchiveScanner
    {
        public string ArchiveFile { get; set; }
        public List<Engines> antivirusDetections { get; set; }
        public Engines engines { get; set; }
        public DeepseekWindow deepseekWindow { get; set; }

        private readonly FileScan fileScan;

        private RetryScan retryScan;
        private UIControl uIControl;
        private List<string> maliciousFilesInArchive = new List<string>();

        public ArchiveScanner(string archiveFile, List<Engines> _antivirusDetections, Engines _engines, DeepseekWindow _deepseekWindow, FileScan _fileScan)
        {
            ArchiveFile = archiveFile;
            antivirusDetections = _antivirusDetections;
            engines = _engines;
            deepseekWindow = _deepseekWindow;
            fileScan = _fileScan;
        }

        public async Task ZipScan(string baseUrl, string filePath, string userFile, string extension,
            Button scanButton, Button showListBoxButton, TextBlock detectionsCountTextBlock,
            Grid columnGrid, ScrollViewer fileScroll, Button showDsButton, TextBlock showTextBlock,
            TextBlock showDSTextBlock, ProgressBar progressBar, JObject archiveAnalysisJson)
        {
            uIControl = new UIControl(antivirusDetections, engines);
            string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(tempPath);
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding archiveEncoding = Encoding.GetEncoding(866);
            int count = 0;
            maliciousFilesInArchive.Clear();

            try
            {
                using (FileStream zipToOpen = new FileStream(ArchiveFile, FileMode.Open))
                {
                    using (ZipArchive archive = new ZipArchive(zipToOpen, ZipArchiveMode.Read, false, archiveEncoding))
                    {
                        RetryScan retryScan = new RetryScan();

                        foreach (ZipArchiveEntry entry in archive.Entries)
                        {
                            uIControl.HideStackPanel(columnGrid, fileScroll, scanButton, showListBoxButton, showDsButton, showTextBlock, detectionsCountTextBlock, showDSTextBlock);
                            progressBar.Visibility = Visibility.Visible;

                            if (string.IsNullOrEmpty(entry.Name)) continue;

                            string relativePath = entry.FullName;
                            string fullTargetPath = Path.Combine(tempPath, relativePath);
                            string directory = Path.GetDirectoryName(fullTargetPath);
                            if (!string.IsNullOrEmpty(directory))
                            {
                                Directory.CreateDirectory(directory);
                            }

                            using (MemoryStream memoryStream = new MemoryStream())
                            {
                                entry.Open().CopyTo(memoryStream);
                                using (FileStream fileStream = new FileStream(fullTargetPath, FileMode.Create, FileAccess.Write, FileShare.Read))
                                {
                                    memoryStream.Position = 0;
                                    memoryStream.CopyTo(fileStream);
                                }
                            }

                            await Task.Delay(50);

                            // ===== СКАНИРУЕМ КАЖДЫЙ ФАЙЛ В АРХИВЕ =====
                            JObject fileAnalysisJson = await retryScan.GetCachedOrScanFile(fullTargetPath, baseUrl, filePath, extension);

                            string status = fileAnalysisJson["data"]?["attributes"]?["status"]?.ToString();
                            if (status != "completed")
                            {
                                MessageBox.Show($"Анализ не завершён. Статус: {status}", "Внимание");
                                return;
                            }

                            await JSONSave.Save(fileAnalysisJson, filePath);

                            AntivirusRankingView antivirusRankingView = new();
                            string stats = antivirusRankingView.ParseAnalysisStatsFile(fileAnalysisJson);
                            ResultMessageBox.Show($"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {filePath} ",
                                            $"Результат сканирования файла {entry.Name}", fileScan);

                            if (ScanResult.IsMalicious(fileAnalysisJson))
                            {
                                count++;
                                maliciousFilesInArchive.Add(entry.FullName);
                                MessageBox.Show("Вредоносный файл, цикл преостановлен");

                                var maliciousChoice = await YesNoDialog.Show("Обнаружен вредоносный файл,\nхотите чтобы ИИ проанализировал его?\nИли нажмите (НЕТ) чтобы продолжить анализ файлов\nИли нажмите на крестик(✕) чтобы остановить скан архива",
                                           "Предупреждение", fileScan);

                                if (maliciousChoice == Choice.Yes)
                                {
                                    // Используем fileAnalysisJson для ИИ
                                    string allEngines = await uIControl.ShowAntivirusNames(fileAnalysisJson, scanButton, showListBoxButton, detectionsCountTextBlock,
                                        columnGrid, fileScroll, showDsButton, showTextBlock, showDSTextBlock);
                                    Log.InfoAboutUserScan(userFile, extension, fileAnalysisJson, stats, allEngines);
                                    progressBar.Visibility = Visibility.Collapsed;

                                    bool isCompleted = await fileScan.WaitForButtonClickAsync();
                                    if (isCompleted)
                                    {
                                        await Task.Delay(5000);
                                        var continueChoice = await YesNoDialog.Show("Вредоносный файл просканирован,\nхотите продолжить сканирование?",
                                           "Предупреждение", fileScan);
                                        if (continueChoice == Choice.Yes)
                                        {
                                            continue;
                                        }
                                        else
                                        {
                                            break;
                                        }
                                    }
                                }
                                else if (maliciousChoice == Choice.No)
                                {
                                    continue;
                                }
                                else
                                {
                                    break;
                                }
                            }
                        }
                    }
                }

                var maliciousFiles = string.Join("\n", maliciousFilesInArchive.Select(d => d));
                ResultMessageBox.Show($"Просканированные вредоносные файлы в этом ZIP архиве:\n{maliciousFiles}\n\nКоличество: {count}", "Список файлов", fileScan);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка в ZipScan: {ex.Message}");
            }
            finally
            {
                if (Directory.Exists(tempPath))
                {
                    Directory.Delete(tempPath, true);
                }
            }
        }

        public async Task RarScan(string baseUrl, string filePath, string userFile, string extension,
            Button scanButton, Button showListBoxButton, TextBlock detectionsCountTextBlock,
            Grid columnGrid, ScrollViewer fileScroll, Button showDsButton, TextBlock showTextBlock,
            TextBlock showDSTextBlock, ProgressBar progressBar, JObject archiveAnalysisJson)
        {
            uIControl = new UIControl(antivirusDetections, engines);
            string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(tempPath);
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            int count = 0;
            maliciousFilesInArchive.Clear();

            try
            {
                using (var archive = ArchiveFactory.OpenArchive(ArchiveFile))
                {
                    RetryScan retryScan = new RetryScan();
                    foreach (var entry in archive.Entries.Where(e => !e.IsDirectory))
                    {
                        uIControl.HideStackPanel(columnGrid, fileScroll, scanButton, showListBoxButton, showDsButton, showTextBlock, detectionsCountTextBlock, showDSTextBlock);
                        progressBar.Visibility = Visibility.Visible;

                        if (string.IsNullOrEmpty(entry.Key)) continue;

                        string relativePath = entry.Key;
                        string fullTargetPath = Path.Combine(tempPath, relativePath);
                        string directory = Path.GetDirectoryName(fullTargetPath);
                        if (!string.IsNullOrEmpty(directory))
                        {
                            Directory.CreateDirectory(directory);
                        }

                        using (MemoryStream memoryStream = new MemoryStream())
                        {
                            entry.OpenEntryStream().CopyTo(memoryStream);
                            using (FileStream fileStream = new FileStream(fullTargetPath, FileMode.Create, FileAccess.Write, FileShare.Read))
                            {
                                memoryStream.Position = 0;
                                memoryStream.CopyTo(fileStream);
                            }
                        }

                        await Task.Delay(50);

                        // ===== СКАНИРУЕМ КАЖДЫЙ ФАЙЛ В АРХИВЕ =====
                        JObject fileAnalysisJson = await retryScan.GetCachedOrScanFile(fullTargetPath, baseUrl, filePath, relativePath);

                        string status = fileAnalysisJson["data"]?["attributes"]?["status"]?.ToString();
                        if (status != "completed")
                        {
                            MessageBox.Show($"Анализ не завершён. Статус: {status}", "Внимание");
                            return;
                        }

                        await JSONSave.Save(fileAnalysisJson, filePath);

                        AntivirusRankingView antivirusRankingView = new();
                        string stats = antivirusRankingView.ParseAnalysisStatsFile(fileAnalysisJson);
                        ResultMessageBox.Show($"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {filePath} ",
                                        $"Результат сканирования файла {entry.Key}", fileScan);

                        if (ScanResult.IsMalicious(fileAnalysisJson))
                        {
                            count++;
                            maliciousFilesInArchive.Add(entry.Key);
                            MessageBox.Show("Вредоносный файл, цикл преостановлен");

                            var maliciousChoice = await YesNoDialog.Show("Обнаружен вредоносный файл,\nхотите чтобы ИИ проанализировал его?\nИли нажмите (НЕТ) чтобы продолжить анализ файлов\nИли нажмите на крестик(✕) чтобы остановить скан архива",
                                       "Предупреждение", fileScan);

                            if (maliciousChoice == Choice.Yes)
                            {
                                // Используем fileAnalysisJson для ИИ
                                string allEngines = await uIControl.ShowAntivirusNames(fileAnalysisJson, scanButton, showListBoxButton, detectionsCountTextBlock,
                                    columnGrid, fileScroll, showDsButton, showTextBlock, showDSTextBlock);
                                Log.InfoAboutUserScan(userFile, extension, fileAnalysisJson, stats, allEngines);
                                progressBar.Visibility = Visibility.Collapsed;

                                bool isCompleted = await fileScan.WaitForButtonClickAsync();
                                if (isCompleted)
                                {
                                    await Task.Delay(2000);
                                    var continueChoice = await YesNoDialog.Show("Вредоносный файл просканирован,\nхотите продолжить сканирование?",
                                       "Предупреждение", fileScan);
                                    if (continueChoice == Choice.Yes)
                                    {
                                        continue;
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }
                            }
                            else if (maliciousChoice == Choice.No)
                            {
                                continue;
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                }

                var maliciousFiles = string.Join("\n", maliciousFilesInArchive.Select(d => d));
                ResultMessageBox.Show($"Просканированные вредоносные файлы в этом RAR архиве:\n{maliciousFiles}\n\nКоличество: {count}", "Список файлов", fileScan);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка в RarScan: {ex.Message}");
            }
            finally
            {
                if (Directory.Exists(tempPath))
                {
                    Directory.Delete(tempPath, true);
                }
            }
        }


        //Методы для проверки на запароленный архив
        public bool IsZipPasswordProtected()
        {
            try
            {
                using (var archive = ZipFile.OpenRead(ArchiveFile))
                {
                    // Если архив запаролен, то при попытке чтения заголовка
                    // может возникнуть исключение или свойство будет указывать на это
                    foreach (var entry in archive.Entries)
                    {
                        // У некоторых библиотек есть свойство IsEncrypted
                        // В стандартном ZipArchive его нет, но можно попробовать прочитать поток
                        try
                        {
                            using (var stream = entry.Open())
                            {
                                // Если файл зашифрован, чтение вызовет исключение
                                byte[] buffer = new byte[1];
                                stream.Read(buffer, 0, 1);
                            }
                        }
                        catch (Exception)
                        {
                            return true; // Не удалось прочитать файл — вероятно, запаролен
                        }
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                // Если архив повреждён или нечитаем
                Debug.WriteLine($"Ошибка при проверке ZIP: {ex.Message}");
                return false;
            }
        }

        public bool IsRarPasswordProtected()
        {
            try
            {
                using (var archive = RarArchive.OpenArchive(ArchiveFile))
                {
                    foreach (var entry in archive.Entries)
                    {
                        if (entry.IsDirectory) continue;

                        // SharpCompress позволяет проверить, зашифрован ли файл
                        if (entry.IsEncrypted)
                        {
                            return true;
                        }
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка при проверке RAR: {ex.Message}");
                return false;
            }
        }

        //Методы для фоновой распаковки архива
        public async Task BackgroundZipScan(string baseUrl, string filePath, string fileName, JObject archiveAnalysisJson)
        {
            uIControl = new UIControl(antivirusDetections, engines);
            string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(tempPath);
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding archiveEncoding = Encoding.GetEncoding(866);
            int count = 0;
            maliciousFilesInArchive.Clear();

            try
            {
                using (FileStream zipToOpen = new FileStream(ArchiveFile, FileMode.Open))
                {
                    using (ZipArchive archive = new ZipArchive(zipToOpen, ZipArchiveMode.Read, false, archiveEncoding))
                    {
                        retryScan = new RetryScan();

                        foreach (ZipArchiveEntry entry in archive.Entries)
                        {
                            uIControl.HideDSWindow();
                            
                            if (string.IsNullOrEmpty(entry.Name)) continue;

                            string relativePath = entry.FullName;
                            string fullTargetPath = Path.Combine(tempPath, relativePath);
                            string directory = Path.GetDirectoryName(fullTargetPath);
                            if (!string.IsNullOrEmpty(directory))
                            {
                                Directory.CreateDirectory(directory);
                            }

                            using (MemoryStream memoryStream = new MemoryStream())
                            {
                                entry.Open().CopyTo(memoryStream);
                                using (FileStream fileStream = new FileStream(fullTargetPath, FileMode.Create, FileAccess.Write, FileShare.Read))
                                {
                                    memoryStream.Position = 0;
                                    memoryStream.CopyTo(fileStream);
                                }
                            }

                            await Task.Delay(50);

                            // ===== СКАНИРУЕМ КАЖДЫЙ ФАЙЛ В АРХИВЕ =====
                            JObject fileAnalysisJson = await retryScan.GetCachedOrScanFile(fullTargetPath, baseUrl, filePath, fileName);

                            string status = fileAnalysisJson["data"]?["attributes"]?["status"]?.ToString();
                            if (status != "completed")
                            {
                                MessageBox.Show($"Анализ не завершён. Статус: {status}", "Внимание");
                                return;
                            }

                            await JSONSave.Save(fileAnalysisJson, filePath);

                            AntivirusRankingView antivirusRankingView = new();
                            string stats = antivirusRankingView.ParseAnalysisStatsFile(fileAnalysisJson);
                            ResultMessageBox.Show($"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {filePath} ",
                                            $"Результат сканирования файла {entry.Name}", fileScan);

                            if (ScanResult.IsMalicious(fileAnalysisJson))
                            {
                                count++;
                                maliciousFilesInArchive.Add(entry.FullName);
                                MessageBox.Show("Вредоносный файл, цикл преостановлен");

                                var maliciousChoice = await YesNoDialog.Show("Обнаружен вредоносный файл,\nхотите чтобы ИИ проанализировал его?\nИли нажмите (НЕТ) чтобы продолжить анализ файлов\nИли нажмите на крестик(✕) чтобы остановить скан архива",
                                           "Предупреждение", fileScan);

                                if (maliciousChoice == Choice.Yes)
                                {
                                    
                                    WindowManager.deepseekWindow = new DeepseekWindow(engines);
                                    await uIControl.AddReplyToWindow(fileAnalysisJson, entry.Name);
                                        await Task.Delay(5000);
                                        var continueChoice = await YesNoDialog.Show("Вредоносный файл просканирован,\nхотите продолжить сканирование?",
                                           "Предупреждение", fileScan);
                                        if (continueChoice == Choice.Yes)
                                        {
                                            continue;
                                        }
                                        else
                                        {
                                            break;
                                        }
                                    
                                }
                                else if (maliciousChoice == Choice.No)
                                {
                                    continue;
                                }
                                else
                                {
                                    break;
                                }
                            }
                        }
                    }
                }

                var maliciousFiles = string.Join("\n", maliciousFilesInArchive.Select(d => d));
                ResultMessageBox.Show($"Просканированные вредоносные файлы в этом ZIP архиве:\n{maliciousFiles}\n\nКоличество: {count}", "Список файлов", fileScan);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка в ZipScan: {ex.Message}");
            }
            finally
            {
                if (Directory.Exists(tempPath))
                {
                    Directory.Delete(tempPath, true);
                }
            }
        }

        public async Task BackgroundRarScan(string baseUrl, string filePath, string extension, JObject archiveAnalysisJson)
        {
            uIControl = new UIControl(antivirusDetections, engines);
            string tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(tempPath);
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            int count = 0;
            maliciousFilesInArchive.Clear();

            try
            {
                using (var archive = ArchiveFactory.OpenArchive(ArchiveFile))
                {
                    RetryScan retryScan = new RetryScan();
                    foreach (var entry in archive.Entries.Where(e => !e.IsDirectory))
                    {
                        uIControl.HideDSWindow();

                        if (string.IsNullOrEmpty(entry.Key)) continue;

                        string relativePath = entry.Key;
                        string fullTargetPath = Path.Combine(tempPath, relativePath);
                        string directory = Path.GetDirectoryName(fullTargetPath);
                        if (!string.IsNullOrEmpty(directory))
                        {
                            Directory.CreateDirectory(directory);
                        }

                        using (MemoryStream memoryStream = new MemoryStream())
                        {
                            entry.OpenEntryStream().CopyTo(memoryStream);
                            using (FileStream fileStream = new FileStream(fullTargetPath, FileMode.Create, FileAccess.Write, FileShare.Read))
                            {
                                memoryStream.Position = 0;
                                memoryStream.CopyTo(fileStream);
                            }
                        }

                        await Task.Delay(50);

                        // ===== СКАНИРУЕМ КАЖДЫЙ ФАЙЛ В АРХИВЕ =====
                        JObject fileAnalysisJson = await retryScan.GetCachedOrScanFile(fullTargetPath, baseUrl, filePath, relativePath);

                        string status = fileAnalysisJson["data"]?["attributes"]?["status"]?.ToString();
                        if (status != "completed")
                        {
                            MessageBox.Show($"Анализ не завершён. Статус: {status}", "Внимание");
                            return;
                        }

                        await JSONSave.Save(fileAnalysisJson, filePath);

                        AntivirusRankingView antivirusRankingView = new();
                        string stats = antivirusRankingView.ParseAnalysisStatsFile(fileAnalysisJson);
                        ResultMessageBox.Show($"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {filePath} ",
                                        $"Результат сканирования файла {entry.Key}", fileScan);

                        if (ScanResult.IsMalicious(fileAnalysisJson))
                        {
                            count++;
                            maliciousFilesInArchive.Add(entry.Key);
                            MessageBox.Show("Вредоносный файл, цикл преостановлен");

                            var maliciousChoice = await YesNoDialog.Show("Обнаружен вредоносный файл,\nхотите чтобы ИИ проанализировал его?\nИли нажмите (НЕТ) чтобы продолжить анализ файлов\nИли нажмите на крестик(✕) чтобы остановить скан архива",
                                       "Предупреждение", fileScan);

                            if (maliciousChoice == Choice.Yes)
                            {
                                // Используем fileAnalysisJson для ИИ
                                WindowManager.deepseekWindow = new DeepseekWindow(engines);
                                await uIControl.AddReplyToWindow(fileAnalysisJson, filePath);
                                await Task.Delay(5000);
                                    var continueChoice = await YesNoDialog.Show("Вредоносный файл просканирован,\nхотите продолжить сканирование?",
                                       "Предупреждение", fileScan);
                                    if (continueChoice == Choice.Yes)
                                    {
                                        continue;
                                    }
                                    else
                                    {
                                        break;
                                    }
                                
                            }
                            else if (maliciousChoice == Choice.No)
                            {
                                continue;
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                }

                var maliciousFiles = string.Join("\n", maliciousFilesInArchive.Select(d => d));
                ResultMessageBox.Show($"Просканированные вредоносные файлы в этом RAR архиве:\n{maliciousFiles}\n\nКоличество: {count}", "Список файлов", fileScan);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка в RarScan: {ex.Message}");
            }
            finally
            {
                if (Directory.Exists(tempPath))
                {
                    Directory.Delete(tempPath, true);
                }
            }
        }


    }
}
