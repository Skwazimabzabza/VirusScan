// ViewModels/MainViewModel.cs
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;

public class MainViewModel : INotifyPropertyChanged
{
    private DownloadMonitorService _monitorService;
    private bool _isMonitoringEnabled;
    private DownloadModel _selectedDownload;

    public MainViewModel()
    {
        _monitorService = DownloadMonitorService.Instance;

        // Привязываем коллекции
        ActiveDownloads = _monitorService.ActiveDownloads;
        CompletedDownloads = _monitorService.CompletedDownloads;

        // Подписываемся на события
        _monitorService.DownloadCompleted += OnDownloadCompleted;
        _monitorService.MonitoringStateChanged += OnMonitoringStateChanged;

        // Команды
        OpenFolderCommand = new RelayCommand(_ => OpenFolder(), _ => SelectedDownload != null);
        OpenFileCommand = new RelayCommand(_ => OpenFile(), _ => SelectedDownload != null);
        ClearHistoryCommand = new RelayCommand(_ => ClearHistory());

        // Загружаем состояние
        IsMonitoringEnabled = _monitorService.IsMonitoring;
    }

    public bool IsMonitoringEnabled
    {
        get => _isMonitoringEnabled;
        set
        {
            if (_isMonitoringEnabled != value)
            {
                _isMonitoringEnabled = value;
                OnPropertyChanged();

                if (value)
                    _monitorService.StartMonitoring();
                else
                    _monitorService.StopMonitoring();
            }
        }
    }

    public ObservableCollection<DownloadModel> ActiveDownloads { get; }
    public ObservableCollection<DownloadModel> CompletedDownloads { get; }

    public DownloadModel SelectedDownload
    {
        get => _selectedDownload;
        set { _selectedDownload = value; OnPropertyChanged(); }
    }

    public ICommand OpenFolderCommand { get; }
    public ICommand OpenFileCommand { get; }
    public ICommand ClearHistoryCommand { get; }

    private void OnMonitoringStateChanged(object sender, bool isActive)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            _isMonitoringEnabled = isActive;
            OnPropertyChanged(nameof(IsMonitoringEnabled));
        });
    }

    private void OnDownloadCompleted(object sender, DownloadModel model)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            // Можно показать уведомление
            // Но не спамим MessageBox, используем статус-бар
        });
    }

    private void OpenFolder()
    {
        if (SelectedDownload != null)
        {
            try
            {
                System.Diagnostics.Process.Start("explorer.exe",
                    $"/select, \"{SelectedDownload.FilePath}\"");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка открытия папки: {ex.Message}");
            }
        }
    }

    private void OpenFile()
    {
        if (SelectedDownload != null && File.Exists(SelectedDownload.FilePath))
        {
            try
            {
                System.Diagnostics.Process.Start(SelectedDownload.FilePath);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка открытия файла: {ex.Message}");
            }
        }
    }

    private void ClearHistory()
    {
        if (MessageBox.Show("Очистить историю загрузок?", "Подтверждение",
            MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            _monitorService.ClearHistory();
        }
    }

    public event PropertyChangedEventHandler PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}