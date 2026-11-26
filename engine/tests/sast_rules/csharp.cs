// Fixture for engine/myelin_engine/rules/sast/csharp.yaml (opengrep --test). Not compiled.
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

public class UsersController : Controller
{
    [HttpGet("users")]
    public IActionResult Users(string q)
    {
        // ruleid: nervve.csharp.sql-injection
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + q + "'", conn);
        // ok: nervve.csharp.sql-injection
        var ok = new SqlCommand("SELECT * FROM users WHERE name = @q", conn);
        return Ok();
    }

    public IActionResult Ping([FromQuery] string host)
    {
        // ruleid: nervve.csharp.command-injection
        Process.Start("cmd.exe", "/c ping " + host);
        return Ok();
    }

    public IActionResult Download([FromQuery] string name)
    {
        // ruleid: nervve.csharp.path-traversal
        var bytes = File.ReadAllBytes("/srv/files/" + name);
        // ok: nervve.csharp.path-traversal
        var safe = File.ReadAllBytes("/srv/files/" + Path.GetFileName(name));
        return Ok();
    }

    public IActionResult Go([FromQuery] string next)
    {
        // ruleid: nervve.csharp.open-redirect
        return Redirect(next);
    }

    public void Hash(byte[] data)
    {
        // ruleid: nervve.csharp.weak-crypto
        var md5 = MD5.Create();
        // ok: nervve.csharp.weak-crypto
        var sha = SHA256.Create();
    }
}
