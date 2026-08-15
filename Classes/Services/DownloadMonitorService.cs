using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Timers;
using System.Windows;
using System.Windows.Threading;


public class DownloadMonitorService
{
    private static DownloadMonitorService _instance;
    public static DownloadMonitorService Instance => _instance ??= new DownloadMonitorService();

    private FileSystemWatcher _watcher;
    private string _downloadsPath;
    private Dictionary<string, System.Timers.Timer> _pendingDownloads = new Dictionary<string, System.Timers.Timer>();
    private Dictionary<string, DownloadModel> _activeDownloads = new Dictionary<string, DownloadModel>();

    public ObservableCollection<DownloadModel> ActiveDownloads { get; } = new ObservableCollection<DownloadModel>();
    public ObservableCollection<DownloadModel> CompletedDownloads { get; } = new ObservableCollection<DownloadModel>();

    public event EventHandler<DownloadModel> DownloadCompleted;
    public event EventHandler<DownloadModel> DownloadStarted;
    public event EventHandler<bool> MonitoringStateChanged;

    private bool _isMonitoring;
    public bool IsMonitoring
    {
        get => _isMonitoring;
        private set
        {
            if (_isMonitoring != value)
            {
                _isMonitoring = value;
                MonitoringStateChanged?.Invoke(this, value);
            }
        }
    }

    private DownloadMonitorService()
    {
        _downloadsPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads";
        if (!Directory.Exists(_downloadsPath))
            _downloadsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Загрузки");
    }

    public void StartMonitoring()
    {
        if (_isMonitoring) return;

        try
        {
            _watcher = new FileSystemWatcher(_downloadsPath);
            _watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite |
                                   NotifyFilters.CreationTime | NotifyFilters.Size;
            _watcher.Filter = "*.*";
            _watcher.IncludeSubdirectories = false;

            _watcher.Created += OnFileCreated;
            _watcher.Renamed += OnFileRenamed;
            _watcher.Changed += OnFileChanged;
            _watcher.Deleted += OnFileDeleted;
            _watcher.Error += OnWatcherError;

            _watcher.EnableRaisingEvents = true;
            IsMonitoring = true;

            Application.Current.Dispatcher.Invoke(() =>
            {
                ActiveDownloads.Clear();
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Ошибка запуска мониторинга: {ex.Message}", "Ошибка",
                           MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    public void StopMonitoring()
    {
        if (!_isMonitoring) return;

        _watcher?.Dispose();
        _watcher = null;

        foreach (var timer in _pendingDownloads.Values)
        {
            timer.Stop();
            timer.Dispose();
        }
        _pendingDownloads.Clear();

        IsMonitoring = false;
    }

    public void ClearHistory()
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            CompletedDownloads.Clear();
        });
    }

    //ОБРАБОТЧИКИ СОБЫТИЙ FileSystemWatcher

    private void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        SafeDispatch(() =>
        {
            if (e.Name.EndsWith(".crdownload") || e.Name.EndsWith(".part") || e.Name.EndsWith(".download"))
            {
                var model = new DownloadModel
                {
                    FileName = Path.GetFileNameWithoutExtension(e.Name),
                    FilePath = e.FullPath,
                    Status = "Скачивается...",
                    Progress = 0,
                    DownloadTime = DateTime.Now
                };

                ActiveDownloads.Add(model);
                _activeDownloads[e.FullPath] = model;

                DownloadStarted?.Invoke(this, model);
                StartTrackingDownload(e.FullPath);
            }
            else
            {
                // Маленькие файлы или файлы без временного расширения
                StartTrackingDownload(e.FullPath, isComplete: true);
            }
        });
    }

    private void OnFileRenamed(object sender, RenamedEventArgs e)
    {
        SafeDispatch(() =>
        {
            // Chrome/Edge: .crdownload -> конечный файл
            // Firefox: .part -> конечный файл
            if (e.OldName.EndsWith(".crdownload") || e.OldName.EndsWith(".part") || e.OldName.EndsWith(".download"))
            {
                var fileInfo = new FileInfo(e.FullPath);

                if (_activeDownloads.TryGetValue(e.OldFullPath, out var model))
                {
                    model.FileName = e.Name;
                    model.FilePath = e.FullPath;
                    model.FileSize = fileInfo.Length;
                    model.Status = "Завершено ✅";
                    model.Progress = 100;
                    model.DownloadTime = DateTime.Now;

                    ActiveDownloads.Remove(model);
                    CompletedDownloads.Insert(0, model);

                    _activeDownloads.Remove(e.OldFullPath);
                    DownloadCompleted?.Invoke(this, model);
                }
                else
                {
                    // Если модель потерялась, создаем новую
                    var newModel = new DownloadModel
                    {
                        FileName = e.Name,
                        FilePath = e.FullPath,
                        FileSize = fileInfo.Length,
                        Status = "Завершено ✅",
                        Progress = 100,
                        DownloadTime = DateTime.Now
                    };
                    CompletedDownloads.Insert(0, newModel);
                    DownloadCompleted?.Invoke(this, newModel);
                }

                StopTrackingDownload(e.OldFullPath);
            }
        });
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        // Обновляем прогресс (только для активных загрузок)
        if (_activeDownloads.TryGetValue(e.FullPath, out var model))
        {
            try
            {
                var fileInfo = new FileInfo(e.FullPath);
                model.FileSize = fileInfo.Length;
                model.Status = $"Скачивается... {FormatFileSize(fileInfo.Length)}";

                // Перезапускаем таймер, чтобы не сработал преждевременно
                if (_pendingDownloads.TryGetValue(e.FullPath, out var timer))
                {
                    timer.Stop();
                    timer.Start();
                }
            }
            catch { }
        }
    }

    private void OnFileDeleted(object sender, FileSystemEventArgs e)
    {
        SafeDispatch(() =>
        {
            if (_activeDownloads.TryGetValue(e.FullPath, out var model))
            {
                model.Status = "Отменено ❌";
                ActiveDownloads.Remove(model);
                _activeDownloads.Remove(e.FullPath);
                StopTrackingDownload(e.FullPath);
            }
        });
    }

    private void OnWatcherError(object sender, ErrorEventArgs e)
    {
        // Логируем ошибку
        System.Diagnostics.Debug.WriteLine($"Ошибка мониторинга: {e.GetException().Message}");
    }

    //ЛОГИКА ОТСЛЕЖИВАНИЯ

    private void StartTrackingDownload(string filePath, bool isComplete = false)
    {
        if (_pendingDownloads.ContainsKey(filePath))
            return;

        if (isComplete && File.Exists(filePath) && !IsFileLocked(filePath))
        {
            SafeDispatch(() =>
            {
                var fileInfo = new FileInfo(filePath);
                var model = new DownloadModel
                {
                    FileName = fileInfo.Name,
                    FilePath = filePath,
                    FileSize = fileInfo.Length,
                    Status = "Завершено ✅",
                    Progress = 100,
                    DownloadTime = DateTime.Now
                };
                CompletedDownloads.Insert(0, model);
                DownloadCompleted?.Invoke(this, model);
            });
            return;
        }

        StartTimerForFile(filePath);
    }

    private void StartTimerForFile(string filePath)
    {
        var timer = new System.Timers.Timer(1000);
        timer.AutoReset = false;
        timer.Elapsed += (sender, e) =>
        {
            if (!File.Exists(filePath))
            {
                StopTrackingDownload(filePath);
                return;
            }

            if (!IsFileLocked(filePath))
            {
                // Файл освободился - загрузка завершена
                SafeDispatch(() =>
                {
                    if (_activeDownloads.TryGetValue(filePath, out var model))
                    {
                        var fileInfo = new FileInfo(filePath);
                        model.FileName = fileInfo.Name;
                        model.FileSize = fileInfo.Length;
                        model.Status = "Завершено ✅";
                        model.Progress = 100;
                        model.DownloadTime = DateTime.Now;

                        ActiveDownloads.Remove(model);
                        CompletedDownloads.Insert(0, model);
                        _activeDownloads.Remove(filePath);
                        DownloadCompleted?.Invoke(this, model);
                    }
                });
                StopTrackingDownload(filePath);
            }
            else
            {
                // Продолжаем проверять
                StartTimerForFile(filePath);
            }
        };

        timer.Start();
        _pendingDownloads[filePath] = timer;
    }

    private void StopTrackingDownload(string filePath)
    {
        if (_pendingDownloads.TryGetValue(filePath, out var timer))
        {
            timer.Stop();
            timer.Dispose();
            _pendingDownloads.Remove(filePath);
        }
    }

    private bool IsFileLocked(string filePath)
    {
        try
        {
            using var fs = File.Open(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
    }

    private string FormatFileSize(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB" };
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len = len / 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }

    //ВСПОМОГАТЕЛЬНЫЙ МЕТОД ДЛЯ БЕЗОПАСНОГО ВЫЗОВА В UI

    private void SafeDispatch(Action action)
    {
        if (Application.Current?.Dispatcher != null && !Application.Current.Dispatcher.HasShutdownStarted)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (Application.Current?.MainWindow != null)
                    action();
            });
        }
    }
}
