import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SymmetricEncryptionOFB1 {

    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    public static byte[] encrypt(String plaintext, SecretKey secretKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        return cipher.doFinal(plaintext.getBytes());
    }

    public static String decrypt(byte[] ciphertext, SecretKey secretKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        return new String(cipher.doFinal(ciphertext));
    }

    public static void main(String[] args) throws Exception {
        SecretKey secretKey = generateKey();
        byte[] iv = new byte[16]; // Initialization vector
        // Generate random IV
        // SecureRandom random = new SecureRandom();
        // random.nextBytes(iv);
        String plaintext = "Hello, world!";
        byte[] ciphertext = encrypt(plaintext, secretKey, iv);
        System.out.println("Ciphertext: " + new String(ciphertext));
        String decryptedText = decrypt(ciphertext, secretKey, iv);
        System.out.println("Decrypted text: " + decryptedText);
    }
}