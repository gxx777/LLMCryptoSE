import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCBC4 {
    
    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/CBC/PKCS5Padding";
    
    private static byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
    
    private static Key generateKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return new SecretKeySpec(key, ALGORITHM);
    }
    
    public static String encrypt(String plaintext, byte[] iv, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    public static String decrypt(String ciphertext, byte[] iv, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            // Generate keys and IVs for three different parties
            Key key1 = generateKey();
            Key key2 = generateKey();
            Key key3 = generateKey();
            
            byte[] iv1 = generateIV();
            byte[] iv2 = generateIV();
            byte[] iv3 = generateIV();
            
            // Encrypt and decrypt messages for each party
            String plaintext1 = "Message for party 1";
            String ciphertext1 = encrypt(plaintext1, iv1, key1);
            String decryptedText1 = decrypt(ciphertext1, iv1, key1);
            System.out.println("Party 1 received: " + decryptedText1);
            
            String plaintext2 = "Message for party 2";
            String ciphertext2 = encrypt(plaintext2, iv2, key2);
            String decryptedText2 = decrypt(ciphertext2, iv2, key2);
            System.out.println("Party 2 received: " + decryptedText2);
            
            String plaintext3 = "Message for party 3";
            String ciphertext3 = encrypt(plaintext3, iv3, key3);
            String decryptedText3 = decrypt(ciphertext3, iv3, key3);
            System.out.println("Party 3 received: " + decryptedText3);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}