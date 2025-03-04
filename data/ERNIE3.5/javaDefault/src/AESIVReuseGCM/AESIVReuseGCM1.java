import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESIVReuseGCM1 {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH = 128; // 16 bytes
    private static final byte[] KEY = "ThisIsASecretKeyThisIsASecretKey".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "ThisIsAnIVThisIsAnIV".getBytes(StandardCharsets.UTF_8); // IV should be unique per encryption session

    public static void main(String[] args) {
        try {
            String plainText1 = "Message 1";
            String plainText2 = "Message 2";
            String plainText3 = "Message 3";

            String encryptedText1 = encrypt(plainText1);
            String encryptedText2 = encrypt(plainText2);
            String encryptedText3 = encrypt(plainText3);

            System.out.println("Encrypted Text 1: " + encryptedText1);
            System.out.println("Encrypted Text 2: " + encryptedText2);
            System.out.println("Encrypted Text 3: " + encryptedText3);

            String decryptedText1 = decrypt(encryptedText1);
            String decryptedText2 = decrypt(encryptedText2);
            String decryptedText3 = decrypt(encryptedText3);

            System.out.println("Decrypted Text 1: " + decryptedText1);
            System.out.println("Decrypted Text 2: " + decryptedText2);
            System.out.println("Decrypted Text 3: " + decryptedText3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String plainText) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, IV);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, IV);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] plainText = cipher.doFinal(bytes);
        return new String(plainText, StandardCharsets.UTF_8);
    }
}