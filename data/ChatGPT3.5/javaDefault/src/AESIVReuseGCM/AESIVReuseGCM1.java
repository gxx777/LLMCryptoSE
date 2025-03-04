import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM1 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "GCM";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 12;

    private static byte[] generateKey() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[KEY_SIZE / 8];
        secureRandom.nextBytes(key);
        return key;
    }

    public static String encrypt(String plainText, byte[] key, byte[] iv) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, byte[] key, byte[] iv) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    public static void main(String[] args) throws Exception {
        byte[] key = generateKey();
        byte[] iv1 = new byte[IV_SIZE];
        byte[] iv2 = new byte[IV_SIZE];
        byte[] iv3 = new byte[IV_SIZE];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv1);
        secureRandom.nextBytes(iv2);
        secureRandom.nextBytes(iv3);

        String plainText1 = "Message for participant 1";
        String plainText2 = "Message for participant 2";
        String plainText3 = "Message for participant 3";

        String cipherText1 = encrypt(plainText1, key, iv1);
        String cipherText2 = encrypt(plainText2, key, iv2);
        String cipherText3 = encrypt(plainText3, key, iv3);

        System.out.println("Cipher text for participant 1: " + cipherText1);
        System.out.println("Cipher text for participant 2: " + cipherText2);
        System.out.println("Cipher text for participant 3: " + cipherText3);

        String decryptedText1 = decrypt(cipherText1, key, iv1);
        String decryptedText2 = decrypt(cipherText2, key, iv2);
        String decryptedText3 = decrypt(cipherText3, key, iv3);

        System.out.println("Decrypted text for participant 1: " + decryptedText1);
        System.out.println("Decrypted text for participant 2: " + decryptedText2);
        System.out.println("Decrypted text for participant 3: " + decryptedText3);
    }
}