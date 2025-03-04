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
//    private static final int TAG_LENGTH = 128; // 16 bytes for AES-256
//    private static final int KEY_LENGTH = 256; // AES-256 key length
//
//    // Encryption
//    public static String encrypt(String plainText, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, key.length * 8);
//        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
//
//        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
//        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
//
//        // Combine the authentication tag with the cipher text
//        byte[] authTag = cipher.getIV();
//        byte[] result = new byte[cipherText.length + authTag.length];
//        System.arraycopy(cipherText, 0, result, 0, cipherText.length);
//        System.arraycopy(authTag, 0, result, cipherText.length, authTag.length);
//
//        return Base64.getEncoder().encodeToString(result);
//    }
//
//    // Decryption
//    public static String decrypt(String cipherTextBase64, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
//        byte[] cipherTextWithAuthTag = Base64.getDecoder().decode(cipherTextBase64);
//        int authTagLength = key.length; // IV length should be equal to key length in GCM mode
//        byte[] cipherText = new byte[cipherTextWithAuthTag.length - authTagLength];
//        byte[] authTag = new byte[authTagLength];
//
//        System.arraycopy(cipherTextWithAuthTag, 0, cipherText, 0, cipherText.length);
//        System.arraycopy(cipherTextWithAuthTag, cipherText.length, authTag, 0, authTag.length);
//
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, key.length * 8, authTag);
//        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
//
//        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
//        byte[] decryptedBytes = cipher.doFinal(cipherText);
//
//        return new String(decryptedBytes, StandardCharsets.UTF_8);
//    }
//
//    // Example usage
//    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
//        String originalText = "This is a secret message to encrypt.";
//        byte[] key = new byte[KEY_LENGTH / 8]; // 32 bytes for AES-256
//
//        // Populate the key with random values (in a real-world scenario, use a secure random generator)
//        for (int i = 0; i < key.length; i++) {
//            key[i] = (byte) i;
//        }
//
//        // Encrypt the original text
//        String encryptedText = encrypt(originalText, key);
//        System.out.println("Encrypted Text: " + encryptedText);
//
//        // Decrypt the encrypted text
//        String decryptedText = decrypt(encryptedText, key);
//        System.out.println("Decrypted Text: " + decryptedText);
//    }
//}