import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM2 {

    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    private SecretKey secretKey;
    private byte[] iv;

    public AESIVReuseGCM2() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            secretKey = keyGen.generateKey();
            
            SecureRandom random = new SecureRandom();
            iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String plaintext, SecretKey secretKey, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            byte[] cipherText = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decrypt(String ciphertext, SecretKey secretKey, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
            byte[] encryptedData = Base64.getDecoder().decode(ciphertext);
            byte[] decryptedText = cipher.doFinal(encryptedData);
            return new String(decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        AESIVReuseGCM2 aes = new AESIVReuseGCM2();
        SecretKey key1 = aes.secretKey;
        byte[] iv1 = aes.iv;

        SecretKey key2 = new SecretKeySpec(key1.getEncoded(), "AES");
        byte[] iv2 = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv2);

        SecretKey key3 = new SecretKeySpec(key1.getEncoded(), "AES");
        byte[] iv3 = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv3);

        String plaintext1 = "Message for participant 1";
        String plaintext2 = "Message for participant 2";
        String plaintext3 = "Message for participant 3";
        
        String ciphertext1 = aes.encrypt(plaintext1, key1, iv1);
        String ciphertext2 = aes.encrypt(plaintext2, key2, iv2);
        String ciphertext3 = aes.encrypt(plaintext3, key3, iv3);

        System.out.println("Ciphertext for participant 1: " + ciphertext1);
        System.out.println("Ciphertext for participant 2: " + ciphertext2);
        System.out.println("Ciphertext for participant 3: " + ciphertext3);

        String decrypted1 = aes.decrypt(ciphertext1, key1, iv1);
        String decrypted2 = aes.decrypt(ciphertext2, key2, iv2);
        String decrypted3 = aes.decrypt(ciphertext3, key3, iv3);

        System.out.println("Decrypted message for participant 1: " + decrypted1);
        System.out.println("Decrypted message for participant 2: " + decrypted2);
        System.out.println("Decrypted message for participant 3: " + decrypted3);
    }
}