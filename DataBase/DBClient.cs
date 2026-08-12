using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusScan2.DataBase
{
    public static class DBClient
    {
        public static Supabase.Client Instance { get; private set; }

        public static async Task Initialize()
        {
            var options = new Supabase.SupabaseOptions
            {
                AutoRefreshToken = true
            };

            Instance = new Supabase.Client(
                "https://cebtmukdnszidqkfqomt.supabase.co",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNlYnRtdWtkbnN6aWRxa2Zxb210Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODI4OTQ2NjYsImV4cCI6MjA5ODQ3MDY2Nn0.bKmYQzTNDG8H2fGKcydgYmnJw_khIfjRcTGce1srl4o",
                options
            );

            await Instance.InitializeAsync();
        }
    }
}
