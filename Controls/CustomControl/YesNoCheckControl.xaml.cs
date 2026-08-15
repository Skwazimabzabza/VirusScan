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
using VirusScan2.Windows.CustomWindow;

namespace VirusScan2.Controls.CustomControl
{
    /// <summary>
    /// Логика взаимодействия для YesNoChoiceControl.xaml
    /// </summary>
    public partial class YesNoCheckControl : Window
    {
        private TaskCompletionSource<Choice> _tcs;

        // DependencyProperties для иконок
        public static readonly DependencyProperty IconGeometryProperty =
            DependencyProperty.Register("IconGeometry", typeof(Geometry), typeof(YesNoDialog));

        public static readonly DependencyProperty IconColorProperty =
            DependencyProperty.Register("IconColor", typeof(Brush), typeof(YesNoDialog));

        public Geometry IconGeometry
        {
            get { return (Geometry)GetValue(IconGeometryProperty); }
            set { SetValue(IconGeometryProperty, value); }
        }

        public Brush IconColor
        {
            get { return (Brush)GetValue(IconColorProperty); }
            set { SetValue(IconColorProperty, value); }
        }

        private YesNoCheckControl(string message, string title)
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

        }

        /// <summary>
        /// Показать диалог Yes/No
        /// </summary>
        public static async Task<Choice> Show(
            string message,
            string title,
            Window owner)
        {
            var dialog = new YesNoCheckControl(message, title);
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

        private void CheckButton_Click(object sender, RoutedEventArgs e)
        {
            _tcs.TrySetResult(Choice.Check);
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
