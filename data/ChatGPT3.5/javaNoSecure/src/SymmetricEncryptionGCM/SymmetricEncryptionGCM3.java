import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionGCM3 {

    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    
    private SecretKey secretKey;

    public SymmetricEncryptionGCM3(byte[] key) {
        secretKey = new SecretKeySpec(key, "AES");
    }

    public String encrypt(String plaintext) {
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            secureRandom.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes());

            byte[] combined = new byte[nonce.length + encrypted.length];
            System.arraycopy(nonce, 0, combined, 0, nonce.length);
            System.arraycopy(encrypted, 0, combined, nonce.length, encrypted.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public String decrypt(String ciphertext) {
        try {
            byte[] combined = Base64.getDecoder().decode(ciphertext);
            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            byte[] encrypted = new byte[combined.length - GCM_NONCE_LENGTH];
            System.arraycopy(combined, 0, nonce, 0, nonce.length);
            System.arraycopy(combined, nonce.length, encrypted, 0, encrypted.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            byte[] decrypted = cipher.doFinal(encrypted);

            return new String(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) {
        byte[] key = new byte[16]; // AES key size: 128 bits
        new SecureRandom().nextBytes(key);

        SymmetricEncryptionGCM3 encryption = new SymmetricEncryptionGCM3(key);

        String plaintext = "Hello, world!";
        String ciphertext = encryption.encrypt(plaintext);
        System.out.println("Ciphertext: " + ciphertext);

        String decryptedText = encryption.decrypt(ciphertext);
        System.out.println("Decrypted Text: " + decryptedText);
    }
}