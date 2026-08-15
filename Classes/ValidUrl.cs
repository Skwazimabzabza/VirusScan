using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusScan2.Classes
{
    public static class ValidUrl
    {
        public static bool IsValidUrl(string url, bool allowLocal = false)
        {
            // 1. Проверка на пустоту
            if (string.IsNullOrWhiteSpace(url))
                return false;

            // 2. Проверка длины (URL не должен быть слишком коротким или длинным)
            if (url.Length < 5 || url.Length > 2048)
                return false;

            // 3. Проверка на наличие пробелов (недопустимо)
            if (url.Contains(" "))
                return false;

            // 4. Проверка на наличие двойных слешей в начале (недопустимо)
            if (url.StartsWith("//"))
                return false;

            // 5. Попытка распарсить URL
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uriResult))
                return false;

            // 6. Проверка схемы (протокола)
            if (!allowLocal && uriResult.IsLoopback)
                return false; // Запрещаем локальные адреса (localhost, 127.0.0.1)

            if (!allowLocal && uriResult.HostNameType == UriHostNameType.IPv4)
            {
                // Запрещаем частные IP-адреса (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
                if (IsPrivateIp(uriResult.Host))
                    return false;
            }

            // 7. Проверка допустимых схем
            string[] allowedSchemes = { "http", "https", "ftp", "ftps" };
            if (!allowedSchemes.Contains(uriResult.Scheme.ToLower()))
                return false;

            // 8. Проверка, что хост содержит точку (если это не localhost и не IP)
            if (!allowLocal && !IsIpAddress(uriResult.Host) && !uriResult.Host.Contains("."))
                return false;

            // 9. Проверка на наличие опасных символов в пути
            string[] dangerous = { "<", ">", "\"", "'", "|", "\\", "`", "$", ";", "&", "(", ")" };
            foreach (var ch in dangerous)
            {
                if (uriResult.PathAndQuery.Contains(ch))
                    return false;
            }

            return true;
        }

        private static bool IsPrivateIp(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;

            // Проверка IPv4
            if (System.Net.IPAddress.TryParse(host, out System.Net.IPAddress ip))
            {
                byte[] bytes = ip.GetAddressBytes();
                // 10.0.0.0/8
                if (bytes[0] == 10) return true;
                // 172.16.0.0/12
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                // 192.168.0.0/16
                if (bytes[0] == 192 && bytes[1] == 168) return true;
                // 127.0.0.0/8 (localhost)
                if (bytes[0] == 127) return true;
            }

            return false;
        }

        private static bool IsIpAddress(string host)
        {
            return System.Net.IPAddress.TryParse(host, out _);
        }
    }
}
