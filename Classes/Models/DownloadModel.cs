// Models/DownloadModel.cs
using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

public class DownloadModel : INotifyPropertyChanged
{
    private string _fileName;
    private string _filePath;
    private long _fileSize;
    private DateTime _downloadTime;
    private string _status;
    private double _progress;

    public string FileName
    {
        get => _fileName;
        set { _fileName = value; OnPropertyChanged(); }
    }

    public string FilePath
    {
        get => _filePath;
        set { _filePath = value; OnPropertyChanged(); }
    }

    public long FileSize
    {
        get => _fileSize;
        set { _fileSize = value; OnPropertyChanged(); }
    }

    public string FileSizeText => FormatFileSize(FileSize);

    public DateTime DownloadTime
    {
        get => _downloadTime;
        set { _downloadTime = value; OnPropertyChanged(); }
    }

    public string Status
    {
        get => _status;
        set { _status = value; OnPropertyChanged(); }
    }

    public double Progress
    {
        get => _progress;
        set { _progress = value; OnPropertyChanged(); }
    }

    public event PropertyChangedEventHandler PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private string FormatFileSize(long bytes)
    {
        if (bytes <= 0) return "0 B";

        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len = len / 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }
}