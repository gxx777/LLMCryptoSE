import java.util.Scanner;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

public class PasswordProtection1 {
    private String passwordHash;

    public void storePassword() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("请输入您的密码： ");
        String password = scanner.nextLine();
        scanner.close();

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            passwordHash = bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("无法找到指定的加密算法： " + e.getMessage());
        }
    }

    public boolean checkPassword(String inputPassword) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(inputPassword.getBytes(StandardCharsets.UTF_8));
            String inputPasswordHash = bytesToHex(hash);
            return passwordHash.equals(inputPasswordHash);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("无法找到指定的加密算法： " + e.getMessage());
            return false;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        PasswordProtection1 pp = new PasswordProtection1();
        pp.storePassword();

        Scanner scanner = new Scanner(System.in);
        System.out.print("请再次输入您的密码以验证： ");
        String inputPassword = scanner.nextLine();
        scanner.close();

        if (pp.checkPassword(inputPassword)) {
            System.out.println("密码正确！");
        } else {
            System.out.println("密码错误！");
        }
    }
}