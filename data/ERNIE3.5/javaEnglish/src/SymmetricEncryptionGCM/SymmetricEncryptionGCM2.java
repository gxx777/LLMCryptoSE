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
//public class SymmetricEncryptionGCM2 {
//
//    private static final String ALGORITHM = "AES/GCM/NoPadding";
//    private static final int TAG_LENGTH = 128; // Length of the authentication tag in bits
//    private static final byte[] KEY = "MySecretKey".getBytes(StandardCharsets.UTF_8); // Replace with your own key
//
//    public static String encrypt(String plainText) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
//        byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
//        byte[] cipherTextBytes = encryptBytes(plainTextBytes);
//        return Base64.getEncoder().encodeToString(cipherTextBytes);
//    }
//
//    public static String decrypt(String cipherText) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
//        byte[] cipherTextBytes = Base64.getDecoder().decode(cipherText);
//        byte[] plainTextBytes = decryptBytes(cipherTextBytes);
//        return new String(plainTextBytes, StandardCharsets.UTF_8);
//    }
//
//    private static byte[] encryptBytes(byte[] plainTextBytes) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
//        SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, KEY.length * 8);
//
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
//
//        byte[] cipherTextBytes = cipher.doFinal(plainTextBytes);
//        return cipherTextBytes;
//    }
//
//    private static byte[] decryptBytes(byte[] cipherTextBytes) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
//        SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, KEY.length * 8);
//
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
//
//        byte[] plainTextBytes = cipher.doFinal(cipherTextBytes);
//        return plainTextBytes;
//    }
//
//    public static void main(String[] args) {
//        String plainText = "Hello, World!";
//        try {
//            String cipherText = encrypt(plainText);
//            System.out.println("Encrypted Text: " + cipherText);
//
//            String decryptedText = decrypt(cipherText);
//            System.out.println("Decrypted Text: " + decryptedText);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}