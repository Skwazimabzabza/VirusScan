using Supabase.Postgrest.Attributes;
using Supabase.Postgrest.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusScan2.DataBase
{
    [Table("urls")]
    public class URLsDB : BaseModel
    {
        [PrimaryKey("id")]
        public long Id { get; set; }

        [Column("url_hash")]
        public string UrlHash { get; set; }

        [Column("url")]
        public string Url { get; set; }

        [Column("analysis_id")]
        public string AnalysisId { get; set; }

        [Column("status")]
        public string Status { get; set; }

        [Column("result_json")]
        public string ResultJson { get; set; }

        [Column("scan_date")]
        public DateTime ScanDate { get; set; }

    }
}
