import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

public class HashExample4 {

    private static final String HASH_ALGORITHM = "SHA-256";

    public static String hashString(String input) throws NoSuchAlgorithmException {
        // 创建一个MessageDigest实例
        MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);

        // 使用utf-8编码将字符串转换为字节
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);

        // 计算哈希值
        byte[] hashBytes = md.digest(inputBytes);

        // 将字节转换为十六进制的字符串
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
    }

    public static void main(String[] args) {
        try {
            String originalString = "Hello, World!";
            String hashedString = hashString(originalString);

            System.out.println("Original String: " + originalString);
            System.out.println("Hashed String: " + hashedString);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}