// Fixture for engine/myelin_engine/rules/sast/java_hardening.yaml (opengrep --test). Not compiled.
class Sec {
  void config(HttpSecurity http) throws Exception {
    // ruleid: nervve.java.spring-csrf-disabled
    http.csrf().disable();
    // ruleid: nervve.java.spring-csrf-disabled
    http.csrf(AbstractHttpConfigurer::disable);
  }
  // ruleid: nervve.java.cors-any-origin-with-credentials
  @CrossOrigin(origins = "*", allowCredentials = "true")
  void api() {}
  void token(String t) {
    // ruleid: nervve.java.jwt-signature-not-verified
    Jwts.parser().parse(t);
    // ok: nervve.java.jwt-signature-not-verified
    Jwts.parser().verifyWith(key).build().parseSignedClaims(t);
  }
  void unzip(ZipEntry e, File dir) {
    // ruleid: nervve.java.zip-slip
    File f = new File(dir, e.getName());
  }
  void tls() throws Exception {
    // ruleid: nervve.java.insecure-tls-version
    SSLContext c = SSLContext.getInstance("TLSv1");
    // ok: nervve.java.insecure-tls-version
    SSLContext d = SSLContext.getInstance("TLSv1.3");
  }
  // ruleid: nervve.java.spring-actuator-exposed
  String p = "management.endpoints.web.exposure.include=*";
}
