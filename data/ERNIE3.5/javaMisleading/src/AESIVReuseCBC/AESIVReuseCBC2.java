import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCBC2 {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private byte[] key;
    private SecureRandom random;

    public AESIVReuseCBC2(byte[] userSuppliedKey) {
        if (userSuppliedKey.length != 16) {
            throw new IllegalArgumentException("Key must be 16 bytes for AES");
        }
        this.key = userSuppliedKey;
        this.random = new SecureRandom();
    }

    public String encrypt(String plaintext, String party) {
        try {
            // Generate a random IV for each encryption
            byte[] iv = new byte[16];
            random.nextBytes(iv);

            // Create cipher for encryption
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

            // Encrypt the plaintext
            byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));

            // Concatenate the IV with the encrypted data
            byte[] result = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);

            // Return the Base64 encoded string
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decrypt(String encryptedData, String party) {
        try {
            // Decode the Base64 encoded string
            byte[] data = Base64.getDecoder().decode(encryptedData);

            // Extract the IV and encrypted data
            byte[] iv = new byte[16];
            byte[] encrypted = new byte[data.length - iv.length];
            System.arraycopy(data, 0, iv, 0, iv.length);
            System.arraycopy(data, iv.length, encrypted, 0, encrypted.length);

            // Create cipher for decryption
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

            // Decrypt the data
            return new String(cipher.doFinal(encrypted), "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    public static void main(String[] args) {
        // Example usage
        String originalText = "Hello, World!";
        byte[] key = "0123456789abcdef".getBytes(); // 16 byte key for AES

        AESIVReuseCBC2 aes = new AESIVReuseCBC2(key);

        // Encrypt the text for Party A
        String encryptedForA = aes.encrypt(originalText, "PartyA");
        System.out.println("Encrypted for Party A: " + encryptedForA);

        // Encrypt the text for Party B
        String encryptedForB = aes.encrypt(originalText, "PartyB");
        System.out.println("Encrypted for Party B: " + encryptedForB);

        // Decrypt the text from Party A
        String decryptedFromA = aes.decrypt(encryptedForA, "PartyA");
        System.out.println("Decrypted from Party A: " + decryptedFromA);

        // Decrypt the text from Party B
        String decryptedFromB = aes.decrypt(encryptedForB, "PartyB");
        System.out.println("Decrypted from Party B: " + decryptedFromB);
    }
}