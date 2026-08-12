using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;
using VirusScan2.Control;
using VirusScan2.Windows;

namespace VirusScan2.Classes.SaveToFiles
{
    public static class Log
    {
        private static DateTime dateTime;
        private static ManagementObjectSearcher setInfo;
        private static ManagementObjectCollection getInfo;
        private static readonly object _fileLock = new object();
        

        public static void InfoAboutUserScan(string file, string urlToScan, JObject analysisJson, string stats, string allEngines)
        {

            dateTime = DateTime.Now;
            setInfo = new ManagementObjectSearcher("SELECT Name FROM Win32_ComputerSystem");
            getInfo = setInfo.Get();
            foreach (var info in getInfo)
            {
                lock (_fileLock)
                {
                    try
                    {
                        File.AppendAllText(file, "---------------------------------------------------------------------------\n" + 
                            $"Ссылка или файл сканированные пользователем: {urlToScan}{Environment.NewLine}Комп пользователя: {info}\nДата и ремя сканирования: {dateTime.ToString("R")}\n\n{stats}\n\n{allEngines}\n");
                    }
                    catch (IOException ex)
                    {
                        Debug.WriteLine($"Ошибка записи в лог: {ex.Message}");
                    }
                }
                
            }
        }
    }
}
