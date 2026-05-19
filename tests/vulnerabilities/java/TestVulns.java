import java.io.*;
import java.sql.*;
import java.net.*;
import java.util.Random;
import javax.servlet.http.*;

public class TestVulns extends HttpServlet {

    // CVI-4001: SQL Injection
    public void sqlInjection(HttpServletRequest request) throws SQLException {
        String user = request.getParameter("user");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
    }

    // CVI-4003: Command Injection
    public void commandInjection(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }

    // CVI-4005: Unsafe Deserialization
    public void unsafeDeserialization(HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.ser"));
        Object obj = ois.readObject();
    }

    // CVI-4009: Hardcoded Password
    public void hardcodedPassword() {
        String password = "admin123456";
        String apiKey = "sk-abc123def456";
    }

    // CVI-4016: Insecure Random
    public void insecureRandom() {
        Random rand = new Random();
        int token = rand.nextInt();
    }

    // CVI-4017: Log4Shell
    public void log4Shell(HttpServletRequest request) {
        String input = request.getParameter("data");
        logger.error("User input: " + input);
    }

    // CVI-4018: Unsafe Reflection
    public void unsafeReflection(HttpServletRequest request) throws Exception {
        String className = request.getParameter("class");
        Class.forName(className);
    }

    // Safe code (should NOT match)
    public void safeCode(HttpServletRequest request) throws SQLException {
        String user = request.getParameter("user");
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        pstmt.setString(1, user);
        ResultSet rs = pstmt.executeQuery();
    }
}
