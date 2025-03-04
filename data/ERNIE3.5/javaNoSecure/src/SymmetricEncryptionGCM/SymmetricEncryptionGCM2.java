//import javax.crypto.Cipher;
//import javax.crypto.KeyGenerator;
//import javax.crypto.SecretKey;
//import javax.crypto.spec.GCMParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//import java.nio.charset.StandardCharsets;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.util.Base64;
//
//public class SymmetricEncryptionGCM2 {
//
//    private static final String ALGORITHM = "AES/GCM/NoPadding";
//    private static final int TAG_LENGTH = 128; // Length of the authentication tag in bits
//    private static final int KEY_SIZE = 256; // Key size in bits
//
//    public static String encrypt(String plainText, String key) throws NoSuchAlgorithmException, InvalidKeyException {
//        SecretKey secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, plainText.getBytes(StandardCharsets.UTF_8).length);
//
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
//
//        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
//        byte[] authTag = cipher.getIV(); // GCM mode uses the same array for IV and authentication tag
//
//        return Base64.getEncoder().encodeToString(cipherText) + ":" + Base64.getEncoder().encodeToString(authTag);
//    }
//
//    public static String decrypt(String cipherTextWithTag, String key) throws NoSuchAlgorithmException, InvalidKeyException {
//        String[] parts = cipherTextWithTag.split(":");
//        byte[] cipherText = Base64.getDecoder().decode(parts[0]);
//        byte[] authTag = Base64.getDecoder().decode(parts[1]);
//
//        SecretKey secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, cipherText.length);
//
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec, authTag);
//
//        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
//    }
//
//    public static void main(String[] args) {
//        try {
//            String key = "myverystrongpassword"; // Replace with your own secure key
//            String plainText = "Hello, GCM mode!";
//
//            // Encrypt
//            String cipherTextWithTag = encrypt(plainText, key);
//            System.out.println("Encrypted Text: " + cipherTextWithTag);
//
//            // Decrypt
//            String decryptedText = decrypt(cipherTextWithTag, key);
//            System.out.println("Decrypted Text: " + decryptedText);
//        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
//            e.printStackTrace();
//        }
//    }
//}