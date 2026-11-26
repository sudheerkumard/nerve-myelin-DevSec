// Fixture for engine/myelin_engine/rules/sast/java.yaml (opengrep --test). Not compiled.
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.crypto.Cipher;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;

public class Fixture extends HttpServlet {

  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String id = request.getParameter("id");
    Connection conn = DriverManager.getConnection("jdbc:h2:mem:");
    Statement st = conn.createStatement();
    // ruleid: nervve.java.sql-injection
    st.executeQuery("SELECT * FROM users WHERE id = " + id);
    // ok: nervve.java.sql-injection
    PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
    // ok: nervve.java.sql-injection
    st.executeQuery("SELECT * FROM users WHERE id = " + Integer.parseInt(id));

    String host = request.getParameter("host");
    // ruleid: nervve.java.command-injection
    Runtime.getRuntime().exec("ping -c 1 " + host);

    String name = request.getParameter("name");
    // ruleid: nervve.java.path-traversal
    FileInputStream in = new FileInputStream("/srv/files/" + name);

    String next = request.getParameter("next");
    // ruleid: nervve.java.open-redirect
    response.sendRedirect(next);

    // ruleid: nervve.java.xss
    response.getWriter().println("<h1>Hello " + name + "</h1>");

    String url = request.getParameter("url");
    // ruleid: nervve.java.ssrf
    java.net.URL u = new java.net.URL(url);
  }
}

@RestController
class Api {
  @GetMapping("/users")
  public Object users(@RequestParam("q") String q, Connection conn) throws Exception {
    Statement st = conn.createStatement();
    // ruleid: nervve.java.sql-injection
    return st.executeQuery("SELECT * FROM users WHERE name = '" + q + "'");
  }

  void crypto() throws Exception {
    // ruleid: nervve.java.weak-crypto
    Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");
    // ruleid: nervve.java.weak-crypto
    MessageDigest md = MessageDigest.getInstance("MD5");
    // ok: nervve.java.weak-crypto
    Cipher g = Cipher.getInstance("AES/GCM/NoPadding");
  }

  Object load(InputStream body) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(body);
    // ruleid: nervve.java.unsafe-deserialisation
    return ois.readObject();
  }
}
