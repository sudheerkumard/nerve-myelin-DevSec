import java.io.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.crypto.Cipher;

public class Orders {
    ResultSet find(Connection c, String id) throws Exception {
        Statement st = c.createStatement();
        ResultSet bad = st.executeQuery("SELECT * FROM orders WHERE id = " + id);   // VULN NM-SAST-021
        PreparedStatement ok = c.prepareStatement("SELECT * FROM orders WHERE id = ?");   // SAFE parameterised
        ok.setString(1, id);
        return ok.executeQuery();
    }
    void run(String file) throws Exception {
        Runtime.getRuntime().exec("convert " + file);                             // VULN NM-SAST-022
        new ProcessBuilder("convert", file).start();                              // SAFE argument list
    }
    Object load(InputStream in) throws Exception {
        return new ObjectInputStream(in).readObject();                            // VULN NM-SAST-023
    }
    byte[] hash(byte[] b) throws Exception {
        MessageDigest.getInstance("MD5").digest(b);                               // VULN NM-SAST-024
        Cipher.getInstance("AES/GCM/NoPadding");                                  // SAFE authenticated encryption
        return MessageDigest.getInstance("SHA-256").digest(b);                    // SAFE strong hash
    }
}
