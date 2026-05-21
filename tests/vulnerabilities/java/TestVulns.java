import java.io.*;
import java.sql.*;
import java.net.*;
import java.util.Random;
import javax.servlet.http.*;

public class TestVulns extends HttpServlet {

    // CVI-6001: SQL Injection (only-regex)
    public void sqlInjection(HttpServletRequest request) throws SQLException {
        String user = request.getParameter("user");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
    }

    // CVI-6003: Command Injection (only-regex)
    public void commandInjection(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }

    // CVI-6005: Unsafe Deserialization (only-regex)
    public void unsafeDeserialization(HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.ser"));
        Object obj = ois.readObject();
    }

    // CVI-6009: Hardcoded Password (only-regex)
    public void hardcodedPassword() {
        String password = "admin123456";
        String apiKey = "sk-abc123def456";
    }

    // CVI-6016: Insecure Random (only-regex)
    public void insecureRandom() {
        Random rand = new Random();
        int token = rand.nextInt();
    }

    // CVI-6018: Unsafe Reflection (only-regex)
    public void unsafeReflection(HttpServletRequest request) throws Exception {
        String className = request.getParameter("class");
        Class.forName(className);
    }

    // CVI-6022: XSS via Response (regex-return-regex)
    public void xssRrr(HttpServletRequest request) throws Exception {
        String user = request.getParameter("user");
        response.getWriter().print("Hello " + user);
    }

    // CVI-6023: ProcessBuilder Command Injection (regex-return-regex)
    public void processBuilderRrr(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.start();
    }

    // CVI-6024: SSRF via URL (regex-return-regex)
    public void ssrfRrr(HttpServletRequest request) throws Exception {
        String url = request.getParameter("url");
        URL u = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
    }

    // CVI-6031: JDBC SQL Injection (function-param-controllable)
    public void sqlInjectionFpc(HttpServletRequest request) throws SQLException {
        String user = request.getParameter("user");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
    }

    // CVI-6032: Command Injection (function-param-controllable)
    public void commandInjectionFpc(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }

    // CVI-6033: File Path Traversal (function-param-controllable)
    public void pathTraversalFpc(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("file");
        FileInputStream fis = new FileInputStream(filename);
    }

    // Safe code - uses PreparedStatement
    public void safeCode(HttpServletRequest request) throws SQLException {
        String user = request.getParameter("user");
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        pstmt.setString(1, user);
        ResultSet rs = pstmt.executeQuery();
    }
}
