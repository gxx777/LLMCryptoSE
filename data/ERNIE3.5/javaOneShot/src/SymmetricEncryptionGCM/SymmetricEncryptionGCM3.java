//import javax.crypto.Cipher;
//import javax.crypto.spec.GCMParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//import java.nio.charset.StandardCharsets;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.util.Base64;
//
//public class SymmetricEncryptionGCM3 {
//
//    private static final String ALGORITHM = "AES/GCM/NoPadding";
//    private static final int TAG_LENGTH = 128; // Tag size in bits
//    private static final int KEY_LENGTH = 256; // Key size in bits
//
//    // Encryption
//    public static String encrypt(String data, String key) throws NoSuchAlgorithmException, InvalidKeyException {
//        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
//        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
//
//        // Create a SecretKeySpec
//        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
//
//        // Create a GCMParameterSpec
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, keyBytes.length * 8);
//
//        // Create a Cipher instance for encryption
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
//
//        // Encrypt the data
//        byte[] encryptedBytes = cipher.doFinal(dataBytes);
//
//        // Return the Base64 encoded encrypted data
//        return Base64.getEncoder().encodeToString(encryptedBytes);
//    }
//
//    // Decryption
//    public static String decrypt(String encryptedData, String key) throws NoSuchAlgorithmException, InvalidKeyException {
//        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
//        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
//
//        // Create a SecretKeySpec
//        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
//
//        // Create a GCMParameterSpec
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, keyBytes.length * 8);
//
//        // Create a Cipher instance for decryption
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
//
//        // Decrypt the data
//        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
//
//        // Return the decrypted string
//        return new String(decryptedBytes, StandardCharsets.UTF_8);
//    }
//
//    public static void main(String[] args) {
//        try {
//            String key = "ThisIsASecretKey12345678"; // 32 bytes key for AES-256
//            String originalData = "This is the data to be encrypted.";
//
//            // Encrypt the data
//            String encryptedData = encrypt(originalData, key);
//            System.out.println("Encrypted Data: " + encryptedData);
//
//            // Decrypt the data
//            String decryptedData = decrypt(encryptedData, key);
//            System.out.println("Decrypted Data: " + decryptedData);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}