// Fixture for engine/myelin_engine/rules/sast/csharp_hardening.yaml (opengrep --test). Not compiled.
class Startup {
  void Configure(IServiceCollection s) {
    var p = new TokenValidationParameters {
      // ruleid: nervve.csharp.jwt-validation-disabled
      ValidateLifetime = false,
      // ruleid: nervve.csharp.jwt-issuer-audience-not-validated
      ValidateIssuer = false
    };
    // ruleid: nervve.csharp.cors-any-origin-with-credentials
    policy.SetIsOriginAllowed(o => true).AllowCredentials();
    var c = new CookieOptions {
      // ruleid: nervve.csharp.insecure-cookie
      Secure = false
    };
    var x = new XmlReaderSettings {
      // ruleid: nervve.csharp.xxe
      DtdProcessing = DtdProcessing.Parse
    };
    // ruleid: nervve.csharp.insecure-tls-version
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11;
  }
  // ruleid: nervve.csharp.antiforgery-disabled
  [IgnoreAntiforgeryToken]
  public IActionResult Post() { return Ok(); }
  string MakeResetToken() {
    // ruleid: nervve.csharp.weak-random-token
    var r = new Random();
    return r.Next().ToString();
  }
}
