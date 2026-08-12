using SharpCompress.Common;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace VirusScan2.Classes
{
    public static class SizeLimiter
    {
        public static bool Limit(string file, int currentSize)
        {
            if (File.Exists(file))
            {
                FileInfo fileInfo = new FileInfo(file);
                long fileSizeInBT = fileInfo.Length;
                double fileSizeInMB = (double)fileSizeInBT / (1024 * 1024);
                double roundedSize = Math.Round(fileSizeInMB, 2);
                if (roundedSize > currentSize)
                {
                    return false;
                }
            }
            return true;
        }
    }
}
