using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace VirusScan2.Classes
{
    public static class InternetConnection
    {
        private static readonly HttpClient httpClient = new HttpClient(new SocketsHttpHandler
        {
            // 0 означает: не кэшировать соединения, для каждого запроса делать новый опрос DNS
            PooledConnectionLifetime = TimeSpan.Zero
        })
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        public static async Task<bool> IsInternetAvailableAsync()
        {
            try
            {
                // Используем метод Head вместо Get, чтобы не скачивать саму страницу (экономит трафик)
                using (var response = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, "https://www.google.com")))
                {
                    return response.IsSuccessStatusCode;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
