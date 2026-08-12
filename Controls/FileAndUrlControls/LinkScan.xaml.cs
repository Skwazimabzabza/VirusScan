using Newtonsoft.Json.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using VirusScan2.Control;
using VirusScan2.Scanning;
using VirusScan2.AntivirusesView;
using VirusScan2.Classes;
using VirusScan2.Windows;
using VirusScan2.Classes.SaveToFiles;

namespace VirusScan2
{
    public partial class LinkScan : Window
    {
        private string BaseUrl = "https://www.virustotal.com/api/v3/";
        private List<Engines> antivirusDetections = new List<Engines>();
        private DeepseekWindow deepseekWindow;
        private UIControl uIControl;
        private Engines engines;
        private string jsonResultFile = "result.json";
        private JObject analysisJson;
        private string urlToScan;

        public LinkScan()
        {

            InitializeComponent();
            LinkTextBox.Text = "http://testsafebrowsing.appspot.com/";
            this.Closed += LinkScan_Closed;
        }

        private async void Button_Scan_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(LinkTextBox.Text) || LinkTextBox.Text == "Вставьте ссылку для сканирования...")
                {
                    return;
                }


                if (!await InternetConnection.IsInternetAvailableAsync())
                {
                    ResultMessageBox.Show("Отсутствует подключение к интернету", "Ошибка", this);
                    return;
                }

                engines = new Engines();
                uIControl = new UIControl(antivirusDetections, engines);
                uIControl.HideStackPanel(ColumnGrid, LinkScroll, ScanButton, ShowButton, ShowDSButton, ShowTextBlock, DetectionsCountTextBlock, DSTextBlock);
                uIControl.ListBoxClear(EnginesListBox);
                AntivirusRankingView antivirusRankingView = new();
                LinkTextBox.GetBindingExpression(TextBox.TextAlignmentProperty)?.UpdateSource();

                var button = sender as Button;
                button.IsEnabled = false;
                Cursor = Cursors.Wait;
                LinkProgressBar.Visibility = Visibility.Visible;


                urlToScan = LinkTextBox.Text.Trim();

                if (!ValidUrl.IsValidUrl(urlToScan))
                {
                    urlToScan = urlToScan.Insert(0, "http://");
                    LinkTextBox.Text = urlToScan;
                }

                // 1. Отправляем на анализ используя метод повторной отправки
                RetryScan retryScan = new();
                analysisJson = await retryScan.GetCachedOrScanUrl(urlToScan, BaseUrl, "application/x-www-form-urlencoded");

                // 3. Форматируем и сохраняем результат
                await JSONSave.Save(analysisJson, jsonResultFile);

                // 4. Показываем основные результаты
                
                string stats = antivirusRankingView.ParseAnalysisStatsUrl(analysisJson);

                ResultMessageBox.Show($"Результаты анализа:\n{stats}\n\nПолные данные сохранены в {jsonResultFile}", "Результат сканирования", this);

                // 5. Показываем антивирусы которые обнаружили вирусы
                string allEngines = await uIControl.ShowAntivirusNames(analysisJson, ScanButton, ShowButton, DetectionsCountTextBlock, ColumnGrid, 
                                                                       LinkScroll, ShowDSButton, ShowTextBlock, DSTextBlock);



                //6. Записываем в файл информацию о ПК пользователя и о том что он сканил
                string userScanFile = "User scan.txt";
                Log.InfoAboutUserScan(userScanFile, urlToScan, analysisJson, stats, allEngines);
                //LinkProgressBar.Visibility = Visibility.Collapsed;
                
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при анализе: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                var button = sender as Button;
                button.IsEnabled = true;
                Cursor = Cursors.Arrow;
                LinkProgressBar.Visibility = Visibility.Collapsed;
            }

        }


        private void ShowButton_Click(object sender, RoutedEventArgs e)
        {
            var eng = string.Join("", antivirusDetections.Select(d => d.AllEngines));

            engines = new Engines();
            deepseekWindow = new DeepseekWindow(engines);
            uIControl = new UIControl(antivirusDetections, engines);
            uIControl.AddEnginesToListBox(eng, ShowButton, ScanButton, EnginesListBox, LinkScroll);
            ColumnDefinition column1 = new ColumnDefinition();
            ColumnDefinition column2 = new ColumnDefinition();


            ColumnGrid.ColumnDefinitions.Add(column1);
            ColumnGrid.ColumnDefinitions.Add(column2);

            column2.Width = new GridLength(50);
            
            ShowTextBlock.Visibility = Visibility.Collapsed;
        }



        private void DeleteButton_Click(object sender, RoutedEventArgs e)
        {
            LinkTextBox.Text = "";
        }

        private void LinkTextBox_GotFocus(object sender, RoutedEventArgs e)
        {
            if (LinkTextBox.Text == "Вставьте ссылку для сканирования...")
            {
                LinkTextBox.Text = "";
                LinkTextBox.Foreground = Brushes.LightSkyBlue;
                LinkTextBox.FontStyle = FontStyles.Normal;
            }
        }

        private void LinkTextBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(LinkTextBox.Text))
            {
                LinkTextBox.Text = "Вставьте ссылку для сканирования...";
                LinkTextBox.Padding = new Thickness(5.4);
                LinkTextBox.Foreground = Brushes.LightSkyBlue;
                LinkTextBox.FontStyle = FontStyles.Normal;
            }
        }

        private async void ShowDS_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var button = sender as Button;
                button.IsEnabled = false;
                ScanButton.IsEnabled = false;
                Cursor = Cursors.Wait;

                DSProgressBar.Visibility = Visibility.Visible;

                uIControl = new UIControl(antivirusDetections, engines);
                await uIControl.AddReplyToWindow(analysisJson, urlToScan);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при анализе ИИ: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
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

        private void LinkScan_Closed(object sender, EventArgs e)
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