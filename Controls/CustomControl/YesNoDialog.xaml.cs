using System;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using VirusScan2.Classes;
using VirusScan2.Controls.CustomControl;

namespace VirusScan2.Windows.CustomWindow
{
    public partial class YesNoDialog : Window
    {
        private TaskCompletionSource<Choice> _tcs;

        private YesNoDialog(string message, string title)
        {
            InitializeComponent();
            DataContext = new MessageViewModel(message, title);

            _tcs = new TaskCompletionSource<Choice>();
            this.MouseDown += (s, args) =>
            {
                if (args.LeftButton == MouseButtonState.Pressed)
                {
                    this.DragMove();
                }
            };
            this.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }

        /// <summary>
        /// Показать диалог Yes/No
        /// </summary>
        public static async Task<Choice> Show(
            string message,
            string title,
            Window owner)
        {
            var dialog = new YesNoDialog(message, title);
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
            dialog.Show();
            return await dialog._tcs.Task;
        }

        /// <summary>
        /// Показать диалог Yes/No/Cancel
        /// </summary>
        

        // Обработчики кнопок
        private void YesButton_Click(object sender, RoutedEventArgs e)
        {
            _tcs.TrySetResult(Choice.Yes);
            Close();
        }

        private void NoButton_Click(object sender, RoutedEventArgs e)
        {
            _tcs.TrySetResult(Choice.No);
            Close();
        }

        private void Close_Button_Click(object sender, RoutedEventArgs e)
        {
            _tcs.TrySetResult(Choice.Cancel);
            Close();
        }

        protected override void OnKeyUp(System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == System.Windows.Input.Key.Enter)
            {
                YesButton_Click(null, null);
            }
            base.OnKeyUp(e);
        }
    }
}