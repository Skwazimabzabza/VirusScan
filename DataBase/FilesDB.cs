using Supabase.Postgrest.Attributes;
using Supabase.Postgrest.Models;

namespace VirusScan2.DataBase
{
    [Table("files")]
    public class FilesDB : BaseModel
    {
        [PrimaryKey("id")]
        public long Id { get; set; }

        [Column("hash")]
        public string Hash { get; set; }

        [Column("file_name")]
        public string FileName {  get; set; }

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
