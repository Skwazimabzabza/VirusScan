using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
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
    /// Логика взаимодействия для ScanMessageBox.xaml
    /// </summary>
    public partial class ResultMessageBox : Window
    {
        public ResultMessageBox(string message, string title)
        {
            InitializeComponent();
            DataContext = new MessageViewModel(message, title);
            this.MouseDown += (s, args) =>
            {
                if (args.LeftButton == MouseButtonState.Pressed)
                {
                    this.DragMove();
                }
            };
            this.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }

        public static void Show(string message, string title, Window owner)
        {
            var dialog = new ResultMessageBox(message, title);
            if (owner != null && owner.IsVisible)
            {
                dialog.Owner = owner;
            }
            else if (Application.Current.MainWindow != null && Application.Current.MainWindow.IsVisible)
            {
                dialog.Owner = Application.Current.MainWindow;
            }
            else
            {
                dialog.Owner = null; // Не устанавливаем Owner, если нет подходящего окна
            }
            dialog.ShowDialog();
        }

        private void Close_Button_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false;
            this.Close();
        }

        private void Ok_Button_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false;
            this.Close();
        }
    }
}
