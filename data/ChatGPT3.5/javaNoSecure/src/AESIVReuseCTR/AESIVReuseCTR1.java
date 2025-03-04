import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR1 {
    
    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CTR/NoPadding";

    private static final String sender1Key = "abcdefghijklmnopqrstuvwxyz123456";
    private static final String sender2Key = "98765poiuytrewqasdfghjklmnbvcxz";
    private static final String sender3Key = "1234567890poiuytrewqasdfghjklm";

    public static void main(String[] args) {
        try {
            // Sender 1 encrypts a message
            String sender1Message = "Hello from Sender 1";
            byte[] sender1Encrypted = encrypt(sender1Message, sender1Key);
            System.out.println("Sender 1 Encrypted Message: " + Base64.getEncoder().encodeToString(sender1Encrypted));
            String sender1Decrypted = decrypt(sender1Encrypted, sender1Key);
            System.out.println("Sender 1 Decrypted Message: " + sender1Decrypted);

            // Sender 2 encrypts a message
            String sender2Message = "Hello from Sender 2";
            byte[] sender2Encrypted = encrypt(sender2Message, sender2Key);
            System.out.println("Sender 2 Encrypted Message: " + Base64.getEncoder().encodeToString(sender2Encrypted));
            String sender2Decrypted = decrypt(sender2Encrypted, sender2Key);
            System.out.println("Sender 2 Decrypted Message: " + sender2Decrypted);

            // Sender 3 encrypts a message
            String sender3Message = "Hello from Sender 3";
            byte[] sender3Encrypted = encrypt(sender3Message, sender3Key);
            System.out.println("Sender 3 Encrypted Message: " + Base64.getEncoder().encodeToString(sender3Encrypted));
            String sender3Decrypted = decrypt(sender3Encrypted, sender3Key);
            System.out.println("Sender 3 Decrypted Message: " + sender3Decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] encrypt(String message, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);
        byte[] iv = generateIV();
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] encrypted = cipher.doFinal(message.getBytes());
        byte[] encryptedWithIV = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, encryptedWithIV, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedWithIV, iv.length, encrypted.length);

        return encryptedWithIV;
    }

    private static String decrypt(byte[] encryptedWithIV, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[encryptedWithIV.length - 16];
        System.arraycopy(encryptedWithIV, 0, iv, 0, 16);
        System.arraycopy(encryptedWithIV, 16, encrypted, 0, encrypted.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(decrypted);
    }

    private static byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }
}