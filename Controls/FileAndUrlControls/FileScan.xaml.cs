using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using VirusScan2.AntivirusesView;
using VirusScan2.Classes;
using VirusScan2.Classes.SaveToFiles;
using VirusScan2.Control;
using VirusScan2.Controls.CustomControl;
using VirusScan2.Scanning;
using VirusScan2.Windows;
using VirusScan2.Windows.CustomWindow;

namespace VirusScan2
{
    /// <summary>
    /// Interaction logic for FileScan.xaml
    /// </summary>
    public partial class FileScan : Window
    {
        private string BaseUrl = "https://www.virustotal.com/api/v3/";
        private List<Engines> antivirusDetections = new List<Engines>();
        private UIControl uIControl;
        private Engines engines;
        private string jsonResultFile = "resultFile.json";
        private OpenFileDialog openFileDialog;
        private string file;
        private string fileName;
        private string extensionName;
        private ArchiveScanner archiveScanner;
        private TaskCompletionSource<bool> _dsButtonClickTcs;
        JObject analysisJson;

        public FileScan()
        {
            InitializeComponent();
            FileTextBox.IsReadOnly = true;
            this.Closed += FileScan_Closed;
        }

        private void OpenDirectory_Button_Click(object sender, RoutedEventArgs e)
        {
            openFileDialog = new OpenFileDialog();
            openFileDialog.ShowDialog();

            file = openFileDialog.FileName;
            
            fileName = System.IO.Path.GetFileName(file);
            FileTextBox.Text = file;
            string filePath = FileTextBox.Text;
            if (string.IsNullOrEmpty(filePath))
            {
                FileTextBox.Text = "Нажмите на кнопку справа для выбора файла";
                return;
                
            }
                
            FileInfo fileInfo = new FileInfo(filePath);          
            long fileSizeInBT = fileInfo.Length;
            double fileSizeInMB = (double)fileSizeInBT / (1024 * 1024);
            double roundedSize = Math.Round(fileSizeInMB, 2);
            if (!SizeLimiter.Limit(filePath, 200))
            {
                ResultMessageBox.Show($"Размер файла не может превышать 100 мб, файл ({fileName}) весит {roundedSize} мб", "Ошибка", this);
                FileTextBox.Text = "Нажмите на кнопку справа для выбора файла";
                return;
            }
            
            FileTextBox.Text = fileName;
        }

        //Кнопка для показа антивирусов
        private void ShowListBoxButton_Click(object sender, RoutedEventArgs e)
        {
            var eng = string.Join("", antivirusDetections.Select(d => d.AllEngines));
            uIControl = new UIControl(antivirusDetections, engines);
            uIControl.AddEnginesToListBox(eng, ShowListBoxButton, ScanButton, EnginesListBox, FileScroll);
            ShowTextBlock.Visibility = Visibility.Collapsed;
            ColumnDefinition column1 = new ColumnDefinition();
            ColumnDefinition column2 = new ColumnDefinition();


            ColumnGrid.ColumnDefinitions.Add(column1);
            ColumnGrid.ColumnDefinitions.Add(column2);

            column2.Width = new GridLength(50);
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(FileTextBox.Text) || FileTextBox.Text == "Нажмите на кнопку справа для выбора файла")
                {
                    return;
                }

                Scan scan = new Scan();
                if (!await InternetConnection.IsInternetAvailableAsync())
                {
                    ResultMessageBox.Show("Отсутствует подключение к инт", "Ошибка", this);
                    return;
                }

                engines = new Engines();

                uIControl = new UIControl(antivirusDetections, engines);
                uIControl.HideStackPanel(ColumnGrid, FileScroll, ScanButton, ShowListBoxButton, ShowDSButton, ShowTextBlock, DetectionsCountTextBlock, ShowDSTextBlock);
                uIControl.ListBoxClear(EnginesListBox);

                FileTextBox.GetBindingExpression(TextBox.TextAlignmentProperty)?.UpdateSource();

                var button = sender as Button;
                button.IsEnabled = false;
                ODButton.IsEnabled = false;
                Cursor = Cursors.Wait;
                FileProgressBar.Visibility = Visibility.Visible;

                RetryScan retryScan = new RetryScan();
                archiveScanner = new ArchiveScanner(file, antivirusDetections, engines, WindowManager.deepseekWindow, this);
                analysisJson = await retryScan.GetCachedOrScanFile(file, BaseUrl, jsonResultFile, fileName);
                AntivirusRankingView antivirusRankingView = new();
                string userScanFile = "User scan.txt";

                extensionName = System.IO.Path.GetExtension(file);
                if (extensionName.Equals(".zip", StringComparison.OrdinalIgnoreCase))
                {
                    if (ScanResult.IsMalicious(analysisJson))
                    {
                        string archiveStats = antivirusRankingView.ParseAnalysisStatsFile(analysisJson);
                        ResultMessageBox.Show($"Результаты анализа:\n{archiveStats}\n\nПолные данные сохранены в {jsonResultFile}", $"Результат сканирования архива\n {fileName}", this);
                        
                        var choice = await YesNoCheckControl.Show("Архив содержит вредоносные файлы либо является вирусным." +
                                "\nХотите распаковать, чтобы посмотреть, какие именно?\nРекомендуется просканировать ИИ",
                                   "Предупреждение", this);
                        // Если пользователь согласен — распаковываем и проверяем каждый файл
                        if (choice == Choice.No || choice == Choice.Cancel)
                        {
                            return;
                        }
                        else if (choice == Choice.Check)
                        {
                            string allEngines = await uIControl.ShowAntivirusNames(analysisJson, ScanButton, ShowListBoxButton, DetectionsCountTextBlock,
                                             ColumnGrid, FileScroll, ShowDSButton, ShowTextBlock, ShowDSTextBlock);
                            Log.InfoAboutUserScan(userScanFile, fileName, analysisJson, archiveStats, allEngines);
                            FileProgressBar.Visibility = Visibility.Collapsed;
                            bool isCompleted = await WaitForButtonClickAsync();
                            if (isCompleted)
                            {
                                await Task.Delay(2000);
                                var beforeAiAnalyse = await YesNoDialog.Show("Архив просканирован ИИ.\nЕсли вредоносный не архив, хотите узнать какой именно файл в нём вредоносный?", "Предупреждение", this);
                                if (beforeAiAnalyse == Choice.Yes)
                                {
                                    FileProgressBar.Visibility = Visibility.Visible;
                                    await archiveScanner.ZipScan(BaseUrl, jsonResultFile, userScanFile, fileName, ScanButton, ShowListBoxButton,
                                    DetectionsCountTextBlock, ColumnGrid, FileScroll, ShowDSButton, ShowTextBlock, ShowDSTextBlock, FileProgressBar, analysisJson);
                                }
                                else if (beforeAiAnalyse == Choice.No)
                                {
                                    return;
                                }
                            }  
                        }

                        else if (choice == Choice.Yes)
                        {
                            if (archiveScanner.IsZipPasswordProtected())
                            {
                                ResultMessageBox.Show($"Архив {fileName} является запароленным.\nРаспаковка невозможна", "Предупреждение", this);
                            }
                            else
                                await archiveScanner.ZipScan(BaseUrl, jsonResultFile, userScanFile, fileName, ScanButton, ShowListBoxButton,
                                    DetectionsCountTextBlock, ColumnGrid, FileScroll, ShowDSButton, ShowTextBlock, ShowDSTextBlock, FileProgressBar, analysisJson);
                        }
                    }
                    else if (ScanResult.IsHarmless(analysisJson))
                    {
                        if (archiveScanner.IsZipPasswordProtected())
                        {
                            ResultMessageBox.Show($"Архив {fileName} является запароленным.\nРекомендуется никак не взамодействовать с ним так как он может быть вредоносным", "Предупреждение", this);
                        }
                        else
                        {
                            string stats = antivirusRankingView.ParseAnalysisStatsFile(analysisJson);
                            ResultMessageBox.Show($"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {jsonResultFile}", $"Результат сканирования архива:\n{fileName}", this);
                        }
                    }
                    
                }
                else if (extensionName.Equals(".rar", StringComparison.OrdinalIgnoreCase))
                {
                    
                    if (ScanResult.IsMalicious(analysisJson))
                    {
                        string archiveStats = antivirusRankingView.ParseAnalysisStatsFile(analysisJson);
                        ResultMessageBox.Show($"Результаты анализа:\n{archiveStats}\n\nПолные данные сохранены в {jsonResultFile}", $"Результат сканирования архива\n {fileName}", this);
                        
                        var choice = await YesNoCheckControl.Show("Архив содержит вредоносные файлы либо является вирусным." +
                                "\nХотите распаковать, чтобы посмотреть, какие именно?\nРекомендуется просканировать ИИ",
                                   "Предупреждение", this);
                        // Если пользователь согласен — распаковываем и проверяем каждый файл
                        if (choice == Choice.No || choice == Choice.Cancel)
                        {
                            return;
                        }
                        else if (choice == Choice.Check)
                        {
                            string allEngines = await uIControl.ShowAntivirusNames(analysisJson, ScanButton, ShowListBoxButton, DetectionsCountTextBlock,
                                             ColumnGrid, FileScroll, ShowDSButton, ShowTextBlock, ShowDSTextBlock);
                            Log.InfoAboutUserScan(userScanFile, fileName, analysisJson, archiveStats, allEngines);
                            FileProgressBar.Visibility = Visibility.Collapsed;
                            bool isCompleted = await WaitForButtonClickAsync();
                            if (isCompleted)
                            {
                                await Task.Delay(2000);
                                var beforeAiAnalyse = await YesNoDialog.Show("Архив просканирован ИИ.\nЕсли вредоносный не архив, хотите узнать какой именно файл в нём вредоносный?", "Предупреждение", this);
                                if (beforeAiAnalyse == Choice.Yes)
                                {
                                    if (!archiveScanner.IsRarPasswordProtected())
                                    {
                                        ResultMessageBox.Show($"Архив {fileName} является запароленным.\nРаспаковка невозможна", "Предупреждение", this);
                                    }
                                    else
                                        await archiveScanner.RarScan(BaseUrl, jsonResultFile, userScanFile, fileName, ScanButton, ShowListBoxButton,
                                        DetectionsCountTextBlock, ColumnGrid, FileScroll, ShowDSButton, ShowTextBlock, ShowDSTextBlock, FileProgressBar, analysisJson);
                                }
                                else if (beforeAiAnalyse == Choice.No)
                                {
                                    return;
                                }
                            }
                        }
                        else if (choice == Choice.Yes)
                        {
                            if (archiveScanner.IsRarPasswordProtected())
                            {
                                ResultMessageBox.Show($"Архив {fileName} является запароленным.\nРаспаковка невозможна", "Предупреждение", this);
                                return;
                            }
                            else
                                await archiveScanner.RarScan(BaseUrl, jsonResultFile, userScanFile, fileName, ScanButton, ShowListBoxButton,
                                    DetectionsCountTextBlock, ColumnGrid, FileScroll, ShowDSButton, ShowTextBlock, ShowDSTextBlock, FileProgressBar, analysisJson);
                        }
                    }

                    else if (ScanResult.IsHarmless(analysisJson))
                    {
                        if (!archiveScanner.IsRarPasswordProtected())
                        {
                            ResultMessageBox.Show($"Архив {fileName} является запароленным.\nРекомендуется никак не взамодействовать с ним так как он может быть вредоносным", "Предупреждение", this);
                        }
                        else
                        {
                            string stats = antivirusRankingView.ParseAnalysisStatsFile(analysisJson);

                            //MessageBox.Show($"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {jsonResultFile}", "Результат сканирования");
                            ResultMessageBox.Show($"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {jsonResultFile}", $"Результат сканирования архива \n{fileName}", this);
                        }
                    }

                    
                }
                else
                {

                    string status = analysisJson["data"]?["attributes"]?["status"]?.ToString();
                    if (status != "completed")
                    {
                        ResultMessageBox.Show($"Анализ не завершён. Статус: {status}", "Внимание", this);
                        return;
                    }

                    string stats = antivirusRankingView.ParseAnalysisStatsFile(analysisJson);

                    //MessageBox.Show($"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {jsonResultFile}", "Результат сканирования");
                    ResultMessageBox.Show($"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {jsonResultFile}", "Результат сканирования", this);

                    string allEngines = await uIControl.ShowAntivirusNames(analysisJson, ScanButton, ShowListBoxButton, DetectionsCountTextBlock,
                    ColumnGrid, FileScroll, ShowDSButton, ShowTextBlock, ShowDSTextBlock);



                    Log.InfoAboutUserScan(userScanFile, fileName, analysisJson, stats, allEngines);
                    FileProgressBar.Visibility = Visibility.Collapsed;


                }
            }
            catch (Exception ex)
            {
                ResultMessageBox.Show($"Ошибка: {ex.Message}", "Ошибка", this);
            }
            finally
            {
                var button = sender as Button;
                button.IsEnabled = true;
                ODButton.IsEnabled = true;
                Cursor = Cursors.Arrow;
                FileProgressBar.Visibility = Visibility.Collapsed;

            }
        }

        public async Task<bool> WaitForButtonClickAsync(CancellationToken cancellationToken = default)
        {
            // Создаём новый TCS для каждого ожидания
            _dsButtonClickTcs = new TaskCompletionSource<bool>();

            // Подписываемся на событие клика
            ShowDSButton.Click += ShowDS_Click;

            try
            {
                using (cancellationToken.Register(() => _dsButtonClickTcs.TrySetCanceled()))
                {
                    return await _dsButtonClickTcs.Task;
                }
            }
            finally
            {
                // ВСЕГДА отписываемся, даже если была отмена или ошибка
                ShowDSButton.Click -= ShowDS_Click;
                _dsButtonClickTcs = null;
            }
        }


        private async void ShowDS_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                e.Handled = true;
                var button = sender as Button;
                button.IsEnabled = false;
                ScanButton.IsEnabled = false;
                Cursor = Cursors.Wait;

                DSProgressBar.Visibility = Visibility.Visible;
                WindowManager.deepseekWindow = new DeepseekWindow(engines);
                uIControl = new UIControl(antivirusDetections, engines);
                await uIControl.AddReplyToWindow(analysisJson, fileName);
                _dsButtonClickTcs?.TrySetResult(true);
            }
            catch (Exception ex)
            {
                ResultMessageBox.Show($"Ошибка при анализе ИИ: {ex.Message}", "Ошибка", this);
            }
            finally
            {
                var button = sender as Button;
                button.IsEnabled = true;
                Cursor = Cursors.Arrow;
                ScanButton.IsEnabled = true;
                DSProgressBar.Visibility = Visibility.Collapsed;


            }
        }

        private void BackButton_Click(object sender, RoutedEventArgs e)
        {
           MainWindow mainWindow = new MainWindow();
           if (WindowManager.deepseekWindow != null)
           {
               WindowManager.deepseekWindow.Close();
               WindowManager.deepseekWindow = null;
           }
           
           this.Close();
           mainWindow.Show();
        }

        private void FileScan_Closed(object sender, EventArgs e)
        {
            // Закрываем DeepseekWindow, если открыт
            if (WindowManager.deepseekWindow != null)
            {
                WindowManager.deepseekWindow.Close();
                WindowManager.deepseekWindow = null;
            }

            // Закрываем все дочерние окна (диалоги)
            foreach (Window window in Application.Current.Windows)
            {
                if (window != this && window.IsVisible)
                {
                    window.Close();
                }
            }

            // Если других окон нет — завершаем приложение
            if (Application.Current.Windows.Count == 0)
            {
                Application.Current.Shutdown();
            }
        }
    }
}
