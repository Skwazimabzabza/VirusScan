using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusScan2.Scanning
{
    public static class ScanResult
    {
        //Метод для проверки вирусные ли ссылка/файл
        public static bool IsMalicious(JObject jsonVTResults)
        {
            var stats = jsonVTResults?["data"]?["attributes"]?["stats"];
            if (((int)stats["malicious"]) > 0 || ((int)stats["suspicious"]) > 0)
            {
                return true;
            }
            return false;
        }

        //Метод для проверки безопасные ли ссылка/файл
        public static bool IsHarmless(JObject jsonVTResults)
        {
            var stats = jsonVTResults?["data"]?["attributes"]?["stats"];
            if (((int)stats["harmless"]) > 0 || ((int)stats["undetected"]) > 0)
            {
                return true;
            }
            return false;
        }
    }
}
