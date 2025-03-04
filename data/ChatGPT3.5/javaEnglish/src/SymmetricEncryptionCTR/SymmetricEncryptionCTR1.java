import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionCTR1 {
    
    private static final String ALGORITHM = "AES";
    private static final String MODE = "CTR";
    private static final int KEY_SIZE = 128;

    public static String encrypt(String keyString, String plaintext) throws Exception {
        Key key = new SecretKeySpec(keyString.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");
        byte[] iv = new byte[KEY_SIZE / 8];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(iv) + Base64.getEncoder().encodeToString(ciphertext);
    }

    public static String decrypt(String keyString, String ciphertext) throws Exception {
        Key key = new SecretKeySpec(keyString.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");
        byte[] iv = Base64.getDecoder().decode(ciphertext.substring(0, KEY_SIZE / 8));
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParams);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext.substring(KEY_SIZE / 8)));
        return new String(decrypted);
    }

    public static void main(String[] args) {
        try {
            String key = "1234567890123456"; // 128-bit key
            String plaintext = "Hello, world!";
            String encrypted = encrypt(key, plaintext);
            System.out.println("Encrypted: " + encrypted);
            String decrypted = decrypt(key, encrypted);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}