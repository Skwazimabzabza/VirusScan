using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using VirusScan2.AntivirusesView;
using VirusScan2.Classes;
using VirusScan2.Classes.SaveToFiles;
using VirusScan2.Control;
using VirusScan2.Controls.CustomControl;
using VirusScan2.Scanning;
using VirusScan2.Windows;
using VirusScan2.Windows.CustomWindow;

namespace VirusScan2.Controls.FileAndUrlControls
{
    /// <summary>
    /// Логика взаимодействия для BackgroundScanning.xaml
    /// </summary>
    public partial class BackgroundScanning : Window
    {
        private DownloadMonitorService _monitorService;
        private AppSettings _settings;
        private string BaseUrl = "https://www.virustotal.com/api/v3/";
        private List<Engines> antivirusDetections = new List<Engines>();
        private UIControl uIControl;
        private Engines engines;
        private string jsonResultFile = "resultFile.json";
        private OpenFileDialog openFileDialog;
        private string fileName;
        private string extension;
        private string extensionName;
        private ArchiveScanner archiveScanner;
        private TaskCompletionSource<bool> _dsButtonClickTcs;
        JObject analysisJson;
        public BackgroundScanning()
        {
            try
            {
                InitializeComponent();
                //MessageBox.Show("BackgroundScanning: Инициализация начата");

                _settings = AppSettings.Load();
                //MessageBox.Show($"BackgroundScanning: Настройки загружены, IsBackgroundMode={_settings.IsBackgroundMode}");

                _monitorService = DownloadMonitorService.Instance;
                //MessageBox.Show("BackgroundScanning: DownloadMonitorService получен");

                _monitorService.DownloadCompleted += OnDownloadCompleted;
                _monitorService.DownloadStarted += OnDownloadStarted;
                _monitorService.MonitoringStateChanged += OnMonitoringStateChanged;

                BackgroundModeCheckBox.IsChecked = _settings.IsBackgroundMode;

                if (_settings.IsBackgroundMode)
                {
                    _monitorService.StartMonitoring();
                    UpdateStatus(true);
                    StatusBarText.Text = "🔄 Фоновый режим активен";
                }

                this.Visibility = Visibility.Visible;
                this.WindowState = WindowState.Normal;
                StatusBarText.Text = "Готов к работе. Поставьте галочку для фонового режима.";

            }
            catch (Exception ex)
            {
                MessageBox.Show($"BackgroundScanning: Ошибка инициализации: {ex.Message}");
                MessageBox.Show($"Ошибка инициализации: {ex.Message}\n\n{ex.StackTrace}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                throw;
            }
        }

        // ========== ОБРАБОТЧИКИ CHECKBOX ==========

        private void BackgroundModeCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            try
            {
                _monitorService.StartMonitoring();
                UpdateStatus(true);
                StatusBarText.Text = "✅ Фоновый режим включен. Окно можно закрыть.";

                _settings.IsBackgroundMode = true;
                _settings.IsMonitoringEnabled = true;
                _settings.Save();

                // Скрываем окно
                this.WindowState = WindowState.Minimized;
                this.Visibility = Visibility.Hidden;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка",
                              MessageBoxButton.OK, MessageBoxImage.Error);
                BackgroundModeCheckBox.IsChecked = false;
            }
        }

        private void BackgroundModeCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            try
            {
                _monitorService.StopMonitoring();
                UpdateStatus(false);
                StatusBarText.Text = "⏹ Мониторинг остановлен";

                _settings.IsBackgroundMode = false;
                _settings.IsMonitoringEnabled = false;
                _settings.Save();

                // Показываем окно
                this.Visibility = Visibility.Visible;
                this.WindowState = WindowState.Normal;

                var result = MessageBox.Show("Остановить мониторинг и выйти из приложения?",
                                            "Выход",
                                            MessageBoxButton.YesNo,
                                            MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    Application.Current.Shutdown();
                }
                else
                {
                    // Возвращаем галочку
                    BackgroundModeCheckBox.IsChecked = true;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка",
                              MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ========== ЗАКРЫТИЕ ОКНА ==========

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            // Если фоновый режим включен - скрываем, иначе закрываем
            if (_settings.IsBackgroundMode && _monitorService.IsMonitoring)
            {
                e.Cancel = true;
                this.Visibility = Visibility.Hidden;
                StatusBarText.Text = "🔄 Приложение работает в фоне";
            }
            else
            {
                _monitorService?.StopMonitoring();
                _settings.IsBackgroundMode = false;
                _settings.IsMonitoringEnabled = false;
                _settings.Save();
            }
        }

        // ========== СОБЫТИЯ МОНИТОРИНГА ==========

        private void OnMonitoringStateChanged(object sender, bool isActive)
        {
            Dispatcher.Invoke(() =>
            {
                UpdateStatus(isActive);
                StatusBarText.Text = isActive ? "🟢 Мониторинг активен" : "🔴 Мониторинг остановлен";
            });
        }

        private void OnDownloadStarted(object sender, DownloadModel model)
        {
            Dispatcher.Invoke(() =>
            {
                StatusBarText.Text = $"⬇️ Скачивается: {model.FileName}";
            });
        }

        private async void OnDownloadCompleted(object sender, DownloadModel model)
        {
            try
            {
                await Dispatcher.InvokeAsync(async () =>
                {
                    StatusBarText.Text = $"✅ Завершено: {model.FileName} ({model.FileSizeText})";

                    if (_settings.IsBackgroundMode)
                    {
                        // ===== ИГНОРИРУЕМ ВРЕМЕННЫЕ ФАЙЛЫ =====
                        if (model.FileName.EndsWith(".tmp") ||
                            model.FileName.EndsWith(".part") ||
                            model.FileName.EndsWith(".crdownload"))
                        {
                            Debug.WriteLine($"Пропущен временный файл: {model.FileName}");
                            return;
                        }
                        // =====================================

                        string filePath = model.FileName.Trim();
                        string fileName = System.IO.Path.GetFileName(filePath);

                        // ===== ПРОВЕРКА: существует ли файл =====
                        if (!File.Exists(filePath))
                        {
                            Debug.WriteLine($"Файл не найден: {filePath}");

                            string directory = System.IO.Path.GetDirectoryName(filePath);

                            if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
                            {
                                string downloadsPath = System.IO.Path.Combine(
                                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                                    "Downloads");

                                string fileNameOnly = System.IO.Path.GetFileName(filePath);
                                string possiblePath = System.IO.Path.Combine(downloadsPath, fileNameOnly);

                                if (File.Exists(possiblePath))
                                {
                                    filePath = possiblePath;
                                    Debug.WriteLine($"Найден файл в Downloads: {filePath}");
                                }
                                else
                                {
                                    StatusBarText.Text = $"❌ Файл не найден: {fileNameOnly}";
                                    return;
                                }
                            }
                            else
                            {
                                var files = Directory.GetFiles(directory, "*" + System.IO.Path.GetFileName(filePath).Replace(" ", "") + "*");
                                if (files.Length > 0)
                                {
                                    filePath = files[0];
                                    Debug.WriteLine($"Найдён похожий файл: {filePath}");
                                }
                                else
                                {
                                    StatusBarText.Text = $"❌ Файл не найден: {System.IO.Path.GetFileName(filePath)}";
                                    return;
                                }
                            }
                        }
                        // =====================================

                        // ===== ПРОВЕРКА РАЗМЕРА =====
                        if (!SizeLimiter.Limit(filePath, 200))
                        {
                            return;
                        }

                        // Даём файлу время на докачку
                        int maxAttempts = 5;
                        long lastSize = 0;
                        bool fileReady = false;

                        for (int attempt = 0; attempt < maxAttempts; attempt++)
                        {
                            try
                            {
                                var fileInfo = new FileInfo(filePath);
                                long currentSize = fileInfo.Length;

                                if (currentSize > 0 && currentSize == lastSize)
                                {
                                    fileReady = true;
                                    break;
                                }

                                lastSize = currentSize;
                                Debug.WriteLine($"Файл растёт: {currentSize} байт, попытка {attempt + 1}");
                                await Task.Delay(1000);
                            }
                            catch (FileNotFoundException)
                            {
                                break;
                            }
                        }

                        if (!fileReady)
                        {
                            Debug.WriteLine($"Файл не готов к сканированию: {filePath}");
                            return;
                        }
                        // =============================

                        var downloadFile = await YesNoDialog.Show(
                            $"Скачан файл: {System.IO.Path.GetFileName(filePath)}\nХотите его просканировать?",
                            "Новый файл",
                            null);

                        if (downloadFile == Choice.Yes)
                        {
                            try
                            {
                                // ===== ИНИЦИАЛИЗИРУЕМ НЕОБХОДИМЫЕ ОБЪЕКТЫ =====
                                if (engines == null)
                                {
                                    engines = new Engines();
                                }
                                if (uIControl == null)
                                {
                                    uIControl = new UIControl(antivirusDetections, engines);
                                }
                                // ============================================

                                string extension = System.IO.Path.GetExtension(filePath);
                                string extensionName = extension; // ← ВАЖНО: используем расширение

                                RetryScan retryScan = new RetryScan();
                                archiveScanner = new ArchiveScanner(filePath, antivirusDetections, engines, WindowManager.deepseekWindow, null);

                                // ===== ПЕРЕДАЁМ ПРАВИЛЬНЫЕ ПАРАМЕТРЫ =====
                                JObject analysisJson = await retryScan.GetCachedOrScanFile(
                                    filePath,
                                    BaseUrl,
                                    jsonResultFile,
                                    fileName); // ← передаём расширение, а не fileName
                                                // ============================================

                                if (analysisJson == null)
                                {
                                    await Dispatcher.InvokeAsync(() =>
                                    {
                                        ResultMessageBox.Show("Не удалось получить результат сканирования.", "Ошибка", null);
                                    });
                                    return;
                                }

                                AntivirusRankingView antivirusRankingView = new();
                                

                                // ===== ПРОВЕРКА НА АРХИВ =====
                                if (extensionName.Equals(".zip", StringComparison.OrdinalIgnoreCase))
                                {
                                    await HandleZipArchive(analysisJson, filePath, fileName, retryScan, antivirusRankingView, archiveScanner);
                                }
                                else if (extensionName.Equals(".rar", StringComparison.OrdinalIgnoreCase))
                                {
                                    await HandleRarArchive(analysisJson, filePath, fileName, retryScan, antivirusRankingView, archiveScanner);
                                }
                                else
                                {
                                    string stats = antivirusRankingView.ParseAnalysisStatsFile(analysisJson);
                                    string allEngines = await ShowAntivirusNamesBackground(analysisJson);
                                    // Обычный файл
                                    await Dispatcher.InvokeAsync(() =>
                                    {
                                        ResultMessageBox.Show(
                                            $"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {jsonResultFile}",
                                            "Результат сканирования",
                                            null);
                                        ResultMessageBox.Show(
                                            $"{allEngines}",
                                            $"Антивирусы обнаружившие угрозу",
                                            null);
                                    });

                                    if (ScanResult.IsMalicious(analysisJson))
                                    {
                                        var dsChoice = await YesNoDialog.Show(
                                            "Этот файл вредоносный.\nХотите проанализировать ИИ для подробной информации?",
                                            "Запрос на ИИ",
                                            null);
                                        if (dsChoice == Choice.Yes)
                                        {
                                            WindowManager.deepseekWindow = new DeepseekWindow(engines);
                                            await uIControl.AddReplyToWindow(analysisJson, fileName);
                                        }
                                    }
                                }
                                // =============================
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine($"Ошибка сканирования: {ex.Message}");
                                await Dispatcher.InvokeAsync(() =>
                                {
                                    ResultMessageBox.Show(
                                        $"Ошибка при сканировании файла: {ex.Message}",
                                        "Ошибка",
                                        null);
                                });
                            }
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка в OnDownloadCompleted: {ex.Message}");
            }
        }

        // ===== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ДЛЯ АРХИВОВ =====

        private async Task HandleZipArchive(JObject analysisJson, string filePath, string extension, RetryScan retryScan, AntivirusRankingView antivirusRankingView, ArchiveScanner archiveScanner)
        {
            string fileName = System.IO.Path.GetFileName(filePath);
            string stats = antivirusRankingView.ParseAnalysisStatsFile(analysisJson);
            string allEngines = await ShowAntivirusNamesBackground(analysisJson);
            if (ScanResult.IsMalicious(analysisJson))
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    ResultMessageBox.Show(
                        $"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {jsonResultFile}",
                        $"Результат сканирования архива:\n{fileName}",
                        null);
                    ResultMessageBox.Show(
                        $"{allEngines}",
                        $"Антивирусы обнаружившие угрозу",
                        null);
                });

                var choice = await YesNoCheckControl.Show(
                    "Архив содержит вредоносные файлы либо является вирусным.\n" +
                    "Хотите распаковать, чтобы посмотреть, какие именно?\n" +
                    "Рекомендуется просканировать ИИ",
                    "Предупреждение",
                    null);

                if (choice == Choice.Yes)
                {
                    if (archiveScanner.IsZipPasswordProtected())
                    {
                        ResultMessageBox.Show($"Архив {fileName} является запароленным.\nРаспаковка невозможна", "Предупреждение", null);
                        return;
                    }
                    await archiveScanner.BackgroundZipScan(BaseUrl, jsonResultFile, fileName, analysisJson);
                }
                else if (choice == Choice.Check)
                {

                    WindowManager.deepseekWindow = new DeepseekWindow(engines);
                    await uIControl.AddReplyToWindow(analysisJson, fileName);
                }
            }
            else
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    ResultMessageBox.Show(
                        $"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {jsonResultFile}",
                        $"Результат сканирования архива:\n{fileName}",
                        null);
                });
            }
        }

        private async Task HandleRarArchive(JObject analysisJson, string filePath, string extension, RetryScan retryScan, AntivirusRankingView antivirusRankingView, ArchiveScanner archiveScanner)
        {
            string fileName = System.IO.Path.GetFileName(filePath);
            string stats = antivirusRankingView.ParseAnalysisStatsFile(analysisJson);
            string allEngines = await ShowAntivirusNamesBackground(analysisJson);

            if (ScanResult.IsMalicious(analysisJson))
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    ResultMessageBox.Show(
                        $"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {jsonResultFile}",
                        $"Результат сканирования архива:\n{fileName}",
                        null);
                    ResultMessageBox.Show($"{allEngines}", "Антивирусы обнаружившие угрозу", null);
                });

                var choice = await YesNoCheckControl.Show(
                    "Архив содержит вредоносные файлы либо является вирусным.\n" +
                    "Хотите распаковать, чтобы посмотреть, какие именно?\n" +
                    "Рекомендуется просканировать ИИ",
                    "Предупреждение",
                    null);

                if (choice == Choice.Yes)
                {
                    if (archiveScanner.IsRarPasswordProtected())
                    {
                        ResultMessageBox.Show($"Архив {fileName} является запароленным.\nРаспаковка невозможна", "Предупреждение", null);
                        return;
                    }
                    await archiveScanner.BackgroundRarScan(BaseUrl, jsonResultFile, fileName, analysisJson);
                }
                else if (choice == Choice.Check)
                {
                    WindowManager.deepseekWindow = new DeepseekWindow(engines);
                    await uIControl.AddReplyToWindow(analysisJson, fileName);
                }
            }
            else
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    ResultMessageBox.Show(
                        $"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {jsonResultFile}",
                        $"Результат сканирования архива:\n{fileName}",
                        null);
                });
            }
        }

        private async Task<string> ShowAntivirusNamesBackground(JObject jsonVTResults)
        {
            antivirusDetections.Clear();
            var antivirusNames = jsonVTResults["data"]?["attributes"]?["results"];
            


            var results = antivirusNames.Children()
            .Where(property =>
            {
                string result = property.First["result"]?.ToString();
                string category = property.First["category"]?.ToString();

                bool isClean = result == "clean" || result == "unrated";
                bool isHarmless = category == "harmless" || category == "undetected" ||
                           category == "failure" || category == "type-unsupported";
                bool isNullResult = string.IsNullOrEmpty(result);

                return !isClean && !isHarmless && !isNullResult;
            })
          .Select(property => new
          {
               engineName = property.First?["engine_name"]?.ToString(),
               result = property.First?["result"]?.ToString() switch
            {
                "malicious" => "вредоносный",
                "suspicious" => "подозрительный",
                "phishing" => "фишинг",
                "clean" => "чистый",
                "unrated" => "не оценено",
                 null => "неизвестно",
                string s when s.Contains("trojan", StringComparison.OrdinalIgnoreCase) => "троян",
                string s when s.Contains("worm", StringComparison.OrdinalIgnoreCase) => "червь",
                string s when s.Contains("ransom", StringComparison.OrdinalIgnoreCase) => "вымогатель",
             _  => property.First?["result"]?.ToString() ?? "неизвестно"
            }
          })
     .Where(name => !string.IsNullOrEmpty(name.engineName))
     .ToList();
            string allEngines = string.Join("\n", results.Select(x => $"Антивирус: {x.engineName}" + "\n" + $"Результат: {x.result}" + "\n"));
            antivirusDetections.Add(new Engines
            {
                AllEngines = allEngines,
            });

            RetryScan retryScan = new();
            if (ScanResult.IsMalicious(jsonVTResults))
            {
                return allEngines;
            }
            else
            {
                return "Угроз не обнаружено";
            }
        }

        private void UpdateStatus(bool isActive)
        {
            //StatusIndicator.Fill = isActive ? new SolidColorBrush(Colors.Green) : new SolidColorBrush(Colors.Red);
            StatusTextBlock.Text = isActive ? "Активен" : "Остановлен";
            StatusTextBlock.Foreground = isActive ? new SolidColorBrush(Colors.LightGreen) : new SolidColorBrush(Colors.Red);
        }

        // ========== ГОРЯЧИЕ КЛАВИШИ ==========

        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);

            // Ctrl+Shift+V - показать окно (если скрыто)
            if (e.Key == Key.V && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
            {
                if (this.Visibility == Visibility.Hidden)
                {
                    this.Visibility = Visibility.Visible;
                    this.WindowState = WindowState.Normal;
                    this.Activate();
                    StatusBarText.Text = "👁 Окно показано";
                }
            }
        }

        protected override void OnMouseDoubleClick(MouseButtonEventArgs e)
        {
            base.OnMouseDoubleClick(e);

            if (this.Visibility == Visibility.Hidden)
            {
                this.Visibility = Visibility.Visible;
                this.WindowState = WindowState.Normal;
                this.Activate();
            }
        }

        private void BackButton_Click(object sender, RoutedEventArgs e)
        {
            MainWindow mainWindow = new MainWindow();
            mainWindow.Show();
            this.Close();
        }
    }
}
