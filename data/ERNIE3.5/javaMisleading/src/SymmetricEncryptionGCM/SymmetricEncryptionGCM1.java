//import javax.crypto.Cipher;
//import javax.crypto.NoSuchPaddingException;
//import javax.crypto.spec.GCMParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//import java.nio.charset.StandardCharsets;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.util.Base64;
//
//public class SymmetricEncryptionGCM1 {
//
//    private static final String ALGORITHM = "AES/GCM/NoPadding";
//    private static final int TAG_LENGTH = 128; // 16 bytes
//    private static final byte[] KEY = "ThisIsASecretKey1234567890".getBytes(StandardCharsets.UTF_8); // 32 bytes
//    private static final byte[] NONCE = "ThisIsANonce12345678".getBytes(StandardCharsets.UTF_8); // 12 bytes
//
//    public static String encrypt(String plainText) throws NoSuchAlgorithmException, InvalidKeyException {
//        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, NONCE);
//
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
//
//        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
//
//        // Combine the ciphertext, tag, and nonce for transmission
//        byte[] result = new byte[cipherText.length + TAG_LENGTH / 8 + NONCE.length];
//        System.arraycopy(NONCE, 0, result, 0, NONCE.length);
//        System.arraycopy(cipherText, 0, result, NONCE.length, cipherText.length);
//        System.arraycopy(cipher.getIV(), 0, result, NONCE.length + cipherText.length, cipher.getIV().length);
//
//        return Base64.getEncoder().encodeToString(result);
//    }
//
//    public static String decrypt(String encryptedText) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
//        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
//        byte[] nonce = new byte[NONCE.length];
//        byte[] cipherText = new byte[encryptedBytes.length - NONCE.length - Cipher.getMaxAllowedIVLength("AES/GCM/NoPadding")];
//        byte[] tag = new byte[encryptedBytes.length - NONCE.length - cipherText.length];
//
//        System.arraycopy(encryptedBytes, 0, nonce, 0, NONCE.length);
//        System.arraycopy(encryptedBytes, NONCE.length, cipherText, 0, cipherText.length);
//        System.arraycopy(encryptedBytes, NONCE.length + cipherText.length, tag, 0, tag.length);
//
//        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, nonce);
//
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
//
//        byte[] decryptedBytes = cipher.doFinal(cipherText, tag);
//
//        return new String(decryptedBytes, StandardCharsets.UTF_8);
//    }
//
//    public static void main(String[] args) {
//        try {
//            String originalText = "Hello, GCM!";
//            String encryptedText = encrypt(originalText);
//            String decryptedText = decrypt(encryptedText);
//
//            System.out.println("Original Text: " + originalText);
//            System.out.println("Encrypted Text: " + encryptedText);
//            System.out.println("Decrypted Text: " + decryptedText);
//        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
//            e.printStackTrace();
//        }
//    }
//}