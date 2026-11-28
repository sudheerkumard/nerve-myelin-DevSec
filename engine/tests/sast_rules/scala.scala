// Fixture for engine/myelin_engine/rules/sast/scala.yaml (opengrep --test). Not compiled.
object Demo {
  def q(st: java.sql.Statement, id: String, request: Request[AnyContent]) = {
    // ruleid: nervve.scala.sql-injection
    st.executeQuery("SELECT * FROM users WHERE id = " + id)
    // ruleid: nervve.scala.sql-injection
    spark.sql(s"SELECT * FROM t WHERE id = $id")
    // ok: nervve.scala.sql-injection
    st.executeQuery("SELECT count(*) FROM users")
    // ruleid: nervve.scala.command-injection
    s"ls $id".!
    // ruleid: nervve.scala.weak-crypto
    val md = MessageDigest.getInstance("SHA-1")
    // ok: nervve.scala.weak-crypto
    val ok = MessageDigest.getInstance("SHA-256")
    // ruleid: nervve.scala.open-redirect
    Redirect(request.getQueryString("next").get)
  }
}

class TrustAll extends X509TrustManager {
  // ruleid: nervve.scala.tls-trust-all
  def checkServerTrusted(chain: Array[X509Certificate], authType: String): Unit = {}
}
