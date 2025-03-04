import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseCBC1 {

    public static void main(String[] args) {
        try {
            // Initialize the secret key and IV
            String secretKey = "ThisIsASecretKey";
            String iv = "1234567890abcdef";
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());

            // Encrypt and decrypt messages for Participant A
            String messageA = "Message for Participant A";
            String encryptedMessageA = encrypt(messageA, secretKeySpec, ivParameterSpec);
            System.out.println("Encrypted message for Participant A: " + encryptedMessageA);
            String decryptedMessageA = decrypt(encryptedMessageA, secretKeySpec, ivParameterSpec);
            System.out.println("Decrypted message for Participant A: " + decryptedMessageA);

            // Encrypt and decrypt messages for Participant B
            String messageB = "Message for Participant B";
            String encryptedMessageB = encrypt(messageB, secretKeySpec, ivParameterSpec);
            System.out.println("Encrypted message for Participant B: " + encryptedMessageB);
            String decryptedMessageB = decrypt(encryptedMessageB, secretKeySpec, ivParameterSpec);
            System.out.println("Decrypted message for Participant B: " + decryptedMessageB);

            // Encrypt and decrypt messages for Participant C
            String messageC = "Message for Participant C";
            String encryptedMessageC = encrypt(messageC, secretKeySpec, ivParameterSpec);
            System.out.println("Encrypted message for Participant C: " + encryptedMessageC);
            String decryptedMessageC = decrypt(encryptedMessageC, secretKeySpec, ivParameterSpec);
            System.out.println("Decrypted message for Participant C: " + decryptedMessageC);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String encrypt(String message, SecretKeySpec secretKey, IvParameterSpec ivParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedMessage, SecretKeySpec secretKey, IvParameterSpec ivParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }
}