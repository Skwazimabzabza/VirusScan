using System;
using System.Collections.Generic;
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
using VirusScan2.Classes;

namespace VirusScan2.Control
{
    /// <summary>
    /// Interaction logic for EnginesWindow.xaml
    /// </summary>
    public partial class DeepseekWindow : Window
    {
        Engines engines;
        public DeepseekWindow(Engines engines)
        {
            InitializeComponent();
            this.engines = engines;
            this.DataContext = engines;
            this.MouseDown += (s, args) =>
            {
                if (args.LeftButton == MouseButtonState.Pressed)
                {
                    this.DragMove();
                }
            };
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();   
        }

        public void ClearContent()
        {
            // Очищаем все элементы управления в окне
            // Например, если у тебя есть TextBlock с ответом ИИ:
            if (this.Content is Grid grid)
            {
                foreach (var child in grid.Children)
                {
                    if (child is TextBlock textBlock)
                    {
                        textBlock.Text = string.Empty;
                    }
                    else if (child is ListBox listBox)
                    {
                        listBox.Items.Clear();
                    }
                    else if (child is RichTextBox richTextBox)
                    {
                        richTextBox.Document.Blocks.Clear();
                    }
                }
            }

            // Или просто очищаем всё содержимое
            this.Content = null;
        }
    }
}
