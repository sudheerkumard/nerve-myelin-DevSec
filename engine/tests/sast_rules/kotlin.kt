// Fixture for engine/myelin_engine/rules/sast/kotlin.yaml (opengrep --test). Not compiled.
package demo

fun load(db: SQLiteDatabase, id: String, st: Statement, wv: WebView) {
    // ruleid: nervve.kotlin.sql-injection
    db.rawQuery("SELECT * FROM users WHERE id = " + id, null)
    // ruleid: nervve.kotlin.sql-injection
    db.rawQuery("SELECT * FROM users WHERE id = ${id}", null)
    // ok: nervve.kotlin.sql-injection
    db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(id))
    // ruleid: nervve.kotlin.command-injection
    Runtime.getRuntime().exec(id)
    // ok: nervve.kotlin.command-injection
    Runtime.getRuntime().exec("ls")
    // ruleid: nervve.kotlin.webview-javascript-bridge
    wv.addJavascriptInterface(Bridge(), "app")
    // ruleid: nervve.kotlin.webview-file-access
    wv.settings.allowFileAccess = true
    // ruleid: nervve.kotlin.weak-crypto
    val c = Cipher.getInstance("AES/ECB/PKCS5Padding")
    // ok: nervve.kotlin.weak-crypto
    val g = Cipher.getInstance("AES/GCM/NoPadding")
    // ruleid: nervve.kotlin.weak-crypto
    val md = MessageDigest.getInstance("MD5")
    // ruleid: nervve.kotlin.world-readable-storage
    val p = getSharedPreferences("x", Context.MODE_WORLD_READABLE)
    // ruleid: nervve.kotlin.cleartext-http
    val url = "http://api.example.com/v1"
    // ok: nervve.kotlin.cleartext-http
    val local = "http://10.0.2.2:8080"
}

class Trust : X509TrustManager {
    // ruleid: nervve.kotlin.tls-verification-disabled
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
}

fun makeToken(): Int {
    // ruleid: nervve.kotlin.insecure-random
    return Random().nextInt()
}

class Client : WebViewClient() {
    override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
        // ruleid: nervve.kotlin.tls-verification-disabled
        handler.proceed()
    }
}

fun intercept(chain: Interceptor.Chain): Response {
    // ok: nervve.kotlin.tls-verification-disabled
    return chain.proceed(chain.request())
}
