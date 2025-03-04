import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class SymmetricEncryptionCBC3 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/CBC/PKCS5Padding";
    private static final String CHARSET = "UTF-8";

    private SecretKeySpec secretKey;
    private IvParameterSpec ivParameterSpec;

    public SymmetricEncryptionCBC3(String keyStr, String ivStr) throws Exception {
        byte[] keyBytes = keyStr.getBytes(CHARSET);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        keyBytes = sha.digest(keyBytes);
        keyBytes = java.util.Arrays.copyOf(keyBytes, 16);
        
        byte[] ivBytes = ivStr.getBytes(CHARSET);
        ivBytes = java.util.Arrays.copyOf(ivBytes, 16);

        secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
        ivParameterSpec = new IvParameterSpec(ivBytes);
    }

    public String encrypt(String input) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(input.getBytes(CHARSET));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String input) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(input));
        return new String(decrypted, CHARSET);
    }

    public static void main(String[] args) {
        try {
            String key = "SecretKey123";
            String iv = "InitialVector123";
            String input = "Hello, world!";
            
            SymmetricEncryptionCBC3 encryption = new SymmetricEncryptionCBC3(key, iv);
            String encrypted = encryption.encrypt(input);
            System.out.println("Encrypted: " + encrypted);
            
            String decrypted = encryption.decrypt(encrypted);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}