//import javax.crypto.BadPaddingException;
//import javax.crypto.Cipher;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.NoSuchPaddingException;
//import javax.crypto.spec.GCMParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//import java.nio.charset.StandardCharsets;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.util.Base64;
//
//public class SymmetricEncryptionGCM3 {
//
//    private static final String ALGORITHM = "AES/GCM/NoPadding";
//    private static final int TAG_LENGTH = 128; // Length of the authentication tag in bits
//    private static final int KEY_LENGTH = 256; // Length of the encryption key in bits
//
//    public static String encrypt(String plaintext, String key) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
//        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
//        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
//
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, keyBytes.length * 8);
//
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
//
//        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
//
//        // Combine the ciphertext with the authentication tag
//        byte[] result = new byte[ciphertext.length + gcmParameterSpec.getIV().length];
//        System.arraycopy(ciphertext, 0, result, 0, ciphertext.length);
//        System.arraycopy(gcmParameterSpec.getIV(), 0, result, ciphertext.length, gcmParameterSpec.getIV().length);
//        return Base64.getEncoder().encodeToString(result);
//    }
//
//    public static String decrypt(String ciphertextBase64, String key) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
//        byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertextBase64);
//
//        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
//        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
//
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, keyBytes.length * 8);
//        gcmParameterSpec.setIV(ciphertextBytes, 0, gcmParameterSpec.getIVLength());
//
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
//
//        byte[] plaintextBytes = cipher.doFinal(ciphertextBytes, gcmParameterSpec.getIVLength(), ciphertextBytes.length - gcmParameterSpec.getIVLength() - gcmParameterSpec.getTLength());
//
//        return new String(plaintextBytes, StandardCharsets.UTF_8);
//    }
//
//    public static void main(String[] args) {
//        String key = "ThisIsASecretKey"; // Replace with your own secure key
//        String plaintext = "Hello, World!";
//
//        try {
//            String encrypted = encrypt(plaintext, key);
//            System.out.println("Encrypted: " + encrypted);
//
//            String decrypted = decrypt(encrypted, key);
//            System.out.println("Decrypted: " + decrypted);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}