using System.Data.SqlClient;
using System.Diagnostics;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;

class Payments {
    void Find(SqlConnection c, string id) {
        var bad = new SqlCommand($"SELECT * FROM payments WHERE id = {id}", c);   // VULN NM-SAST-031
        var ok = new SqlCommand("SELECT * FROM payments WHERE id = @id", c);      // SAFE parameterised
        ok.Parameters.AddWithValue("@id", id);
    }
    object Load(System.IO.Stream s) { return new BinaryFormatter().Deserialize(s); }   // VULN NM-SAST-032
    void Trust() {
        ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true;   // VULN NM-SAST-033
    }
    void Run(string f) {
        Process.Start("cmd.exe", "/c convert " + f);                              // VULN NM-SAST-034
        Process.Start(new ProcessStartInfo("convert") { ArgumentList = { f } });  // SAFE argument list
    }
}
