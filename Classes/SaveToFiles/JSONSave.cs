using Newtonsoft.Json.Linq;
using SharpCompress.Common;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusScan2.Classes.SaveToFiles
{
//Метод для сохранения ответа от VT в файл
    public static class JSONSave
    {
        public static async Task Save(JObject analysisJson, string filePath)
        {
            string formattedJson = analysisJson.ToString(Newtonsoft.Json.Formatting.Indented);
            await File.WriteAllTextAsync(filePath, formattedJson);
        }
    }
}
