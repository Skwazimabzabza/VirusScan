using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using VirusScan2.AI;
using VirusScan2.Classes;
using VirusScan2.Controls.CustomControl;
using VirusScan2.Scanning;
using VirusScan2.Windows;

namespace VirusScan2.Control
{
    public class UIControl
    {
        public List<Engines> antivirusDetections { get; set; }
        public Engines engines { get; set; }
        public UIControl(List<Engines> _antivirusDetections, Engines _engines)
        {
            antivirusDetections = _antivirusDetections;
            engines = _engines;
            
        }
        public async Task<string> ShowAntivirusNames(JObject jsonVTResults, Button scanButton, Button showButton, TextBlock detectionsCountTextBlock,
            Grid columnGrid, ScrollViewer scrollViewer, Button dsButton, TextBlock showTextBlock, TextBlock dsTextBlock)
        {
            antivirusDetections.Clear();
            var antivirusNames = jsonVTResults["data"]?["attributes"]?["results"];
            if (antivirusNames == null)
            {
                HideStackPanel(columnGrid, scrollViewer, scanButton, showButton, dsButton, showTextBlock, detectionsCountTextBlock, dsTextBlock);
                return "Нет данных от об антивирусах";
            }


            var results = antivirusNames.Children()
     .Where(property =>
     {
         string result = property.First["result"]?.ToString();
         string category = property.First["category"]?.ToString();

         // Исключаем:
         // 1. result == "clean" или "unrated"
         // 2. category == "undetected", "harmless", "failure", "type-unsupported"
         // 3. result == null (т.к. это обычно означает "не обнаружено")

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
             _ => property.First?["result"]?.ToString() ?? "неизвестно"
         }
     })
     .Where(name => !string.IsNullOrEmpty(name.engineName))
     .ToList();
            string allEngines = string.Join("\n", results.Select(x => $"Антивирус: {x.engineName}" + "\n" + $"Результат: {x.result}" + "\n"));

            //ResultComboBox.Items.Add(allEngines);
            //Engines engines = new Engines();
            //engines.AllEngines = allEngines;
            //EnginesWindow enginesWindow = new EnginesWindow(engines);
            //enginesWindow.Show();



            antivirusDetections.Add(new Engines
            {
                AllEngines = allEngines,
            });

            RetryScan retryScan = new();
            if (ScanResult.IsMalicious(jsonVTResults))
            {
                ShowElements(results.Count(), scanButton, showButton, detectionsCountTextBlock,  dsButton, showTextBlock, dsTextBlock);
                return allEngines;
            }
            else
            {
                return "Угроз не обнаружено";
            }
        }

        public async Task AddReplyToWindow(JObject file, string name)
        {

            DeepSeekAPI deepSeekAPI = new DeepSeekAPI();
            string deepseekReply = await deepSeekAPI.SendRequestToAI(file, name);

            antivirusDetections.Add(new Engines
            {
                DeepseekReply = deepseekReply,
            });
            ShowDeepseekWindow();
        }

        private void ShowDeepseekWindow()
        {
            var combinedDeepseek = string.Join("", antivirusDetections.Select(a => a.DeepseekReply));
            engines = new Engines
            {
                DeepseekReply = combinedDeepseek,
            };
            WindowManager.deepseekWindow = new DeepseekWindow(engines);
            WindowManager.deepseekWindow.Show();
            File.AppendAllText("User scan.txt", $"Анализ от ИИ:\n{engines.DeepseekReply}\n");
        }

        private void ShowElements(int detectionCount, Button scanButton, Button showButton, TextBlock detectionsCountTextBlock,
            Button dsButton, TextBlock showTextBlock, TextBlock dsTextBlock)
        {
            //ComboBoxStackPanel.Visibility = Visibility.Visible;
            //ComboBoxStackPanel.Height = 145;
            //clickToSee.Visibility = Visibility.Visible;
            //ResultComboBox.Visibility = Visibility.Visible;
            detectionsCountTextBlock.Visibility = Visibility.Visible;
            detectionsCountTextBlock.Text = $"Количество обнаружений: {detectionCount}";

            showTextBlock.Visibility = Visibility.Visible;

            
            //clickToSee.Visibility = Visibility.Visible;

            dsButton.Visibility = Visibility.Visible;
            dsTextBlock.Visibility = Visibility.Visible;

            
            scanButton.Visibility = Visibility.Hidden;
            showButton.Visibility = Visibility.Visible;


        }

        public void AddEnginesToListBox(string eng, Button showButton, Button scanButton, ListBox enginesListBox, ScrollViewer scrollViewer)
        {
            engines = new Engines
            {
                AllEngines = eng,
            };
            if (!enginesListBox.Items.Contains(eng))
            {

                enginesListBox.Items.Add(eng);
            }

            scrollViewer.Visibility = Visibility.Visible;

            showButton.Visibility = Visibility.Hidden;
            scanButton.Visibility = Visibility.Visible;
        }

        public void HideStackPanel(Grid columnGrid, ScrollViewer scrollViewer, Button scanButton, Button showButton, Button dsButton, TextBlock showTextBlock,
            TextBlock detectionsCountTextBlock, TextBlock dsTextBlock)
        {
            // Скрываем все элементы UI
            //ComboBoxStackPanel.Visibility = Visibility.Hidden;
            //ComboBoxStackPanel.Height = 0;
            //clickToSee.Visibility = Visibility.Hidden;
            //ResultComboBox.Visibility = Visibility.Hidden;
            if(detectionsCountTextBlock.Visibility == Visibility.Visible)
            {
                detectionsCountTextBlock.Visibility = Visibility.Collapsed;
            }
            
            if(scrollViewer.Visibility == Visibility.Visible)
            {
                scrollViewer.Visibility = Visibility.Collapsed;
            }
            

            // Очищаем текст
            //DetectionsCountTextBlock.Text = "";

            // Удаляем вторую колонку если она существует
            if (columnGrid.ColumnDefinitions.Count >= 2)
            {
                // Сначала нужно переместить или удалить элементы из удаляемой колонки
                var elementsToRemove = new List<UIElement>();

                foreach (UIElement child in columnGrid.Children)
                {
                    if (Grid.GetColumn(child) == 1) // Если элемент во второй колонке
                    {
                        elementsToRemove.Add(child);
                    }
                }

                // Удаляем найденные элементы
                foreach (var element in elementsToRemove)
                {
                    columnGrid.Children.Remove(element);
                }

                // Удаляем саму колонку (всегда удаляем последнюю)
                columnGrid.ColumnDefinitions.RemoveAt(columnGrid.ColumnDefinitions.Count - 1);
                
            }

            // Возвращаем видимость кнопкам
            if(scanButton.Visibility == Visibility.Hidden)
            {
                scanButton.Visibility = Visibility.Visible;
            }
            
            if(showButton.Visibility == Visibility.Visible)
            {
                showButton.Visibility = Visibility.Collapsed;
            }
            
            if(showTextBlock.Visibility == Visibility.Visible)
            {
                showTextBlock.Visibility = Visibility.Collapsed;
            }
            
            if(dsTextBlock.Visibility == Visibility.Visible)
            {
                dsTextBlock.Visibility = Visibility.Collapsed;
            }
            
            if(dsButton.Visibility == Visibility.Visible)
            {
                dsButton.Visibility = Visibility.Collapsed;
            }

            HideDSWindow();
            
        }

        public void HideDSWindow()
        {
            if (WindowManager.deepseekWindow != null)
            {
                WindowManager.deepseekWindow.Close();
                WindowManager.deepseekWindow = null;
            }
            // Очищаем engines
            if (engines != null)
            {
                engines.DeepseekReply = string.Empty;
                engines.AllEngines = string.Empty;
            }

            // Очищаем antivirusDetections
            antivirusDetections.Clear();
        }

        public void ListBoxClear(ListBox listBox)
        {
            if(listBox.Items != null)
            {
                listBox.Items.Clear();
            }
        }
    }
}
