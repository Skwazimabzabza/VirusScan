using Microsoft.Win32;
using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using VirusScan2.AntivirusesView;
using VirusScan2.Classes;
using VirusScan2.Control;
using VirusScan2.Controls.CustomControl;
using VirusScan2.Controls.FileAndUrlControls;
using VirusScan2.Scanning;
using VirusScan2.Windows;
using VirusScan2.Windows.CustomWindow;

namespace VirusScan2
{
    public partial class MainWindow : Window
    {
        
        public MainWindow()
        {
            InitializeComponent();
            
        }

        private void LinkScan_Button_Click(object sender, RoutedEventArgs e)
        {
            LinkScan linkScan = new LinkScan();
            linkScan.Show();
            this.Close();
        }

        private void FileScan_Button_Click(object sender, RoutedEventArgs e)
        {
            FileScan fileScan = new FileScan();
            fileScan.Show();
            this.Close();
        }

        private void BackgroundScan_Button_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var bgWindow = new BackgroundScanning();
                bgWindow.Show();
                // Не закрывай MainWindow, если он нужен
                this.Hide(); // или this.Close() — смотри по ситуации
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка открытия: {ex.Message}");
            }
        }

        // ========== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ==========


    }
}