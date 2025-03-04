import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESIVReuseGCM3 {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_MODE = "GCM";
    private static final int AES_KEY_SIZE = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    private SecretKeySpec secretKey;

    public AESIVReuseGCM3(String key) {
        this.secretKey = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);
    }

    public String encrypt(String plaintext, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM + "/" + AES_MODE + "/" + "NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String ciphertext, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM + "/" + AES_MODE + "/" + "NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] decodedCiphertext = Base64.getDecoder().decode(ciphertext);
        byte[] decryptedBytes = cipher.doFinal(decodedCiphertext);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        String key = "abcdefghijklmnopqrstuvwxyzt123456"; // 256-bit key
        AESIVReuseGCM3 aesGcm = new AESIVReuseGCM3(key);

        try {
            // Participant 1
            byte[] iv1 = new byte[GCM_IV_LENGTH];
            // Generate random IV for Participant 1
            // send message
            String ciphertext1 = aesGcm.encrypt("Message for Participant 1", iv1);
            System.out.println("Encrypted message for Participant 1: " + ciphertext1);
            String decryptedText1 = aesGcm.decrypt(ciphertext1, iv1);
            System.out.println("Decrypted message for Participant 1: " + decryptedText1);

            // Participant 2
            byte[] iv2 = new byte[GCM_IV_LENGTH];
            // Generate random IV for Participant 2
            // send message
            String ciphertext2 = aesGcm.encrypt("Message for Participant 2", iv2);
            System.out.println("Encrypted message for Participant 2: " + ciphertext2);
            String decryptedText2 = aesGcm.decrypt(ciphertext2, iv2);
            System.out.println("Decrypted message for Participant 2: " + decryptedText2);

            // Participant 3
            byte[] iv3 = new byte[GCM_IV_LENGTH];
            // Generate random IV for Participant 3
            // send message
            String ciphertext3 = aesGcm.encrypt("Message for Participant 3", iv3);
            System.out.println("Encrypted message for Participant 3: " + ciphertext3);
            String decryptedText3 = aesGcm.decrypt(ciphertext3, iv3);
            System.out.println("Decrypted message for Participant 3: " + decryptedText3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}