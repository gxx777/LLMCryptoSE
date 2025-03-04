//import javax.crypto.BadPaddingException;
//import javax.crypto.Cipher;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.spec.IvParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//import java.nio.charset.StandardCharsets;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.util.Arrays;
//
//public class SymmetricEncryptionCTR3 {
//
//    private static final String ALGORITHM = "AES/CTR/NoPadding";
//    private static final byte[] KEY = "0123456789abcdef".getBytes(StandardCharsets.UTF_8); // 16-byte key
//    private static final byte[] NONCE = "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8); // 16-byte nonce
//
//    public static String encrypt(String input) throws NoSuchAlgorithmException, InvalidKeyException, java.security.InvalidAlgorithmParameterException {
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
//        IvParameterSpec ivParameterSpec = new IvParameterSpec(NONCE);
//        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
//
//        byte[] encrypted = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
//        return Arrays.toString(encrypted);
//    }
//
//    public static String decrypt(String encrypted) throws NoSuchAlgorithmException, InvalidKeyException, java.security.InvalidAlgorithmParameterException {
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY, "AES");
//        IvParameterSpec ivParameterSpec = new IvParameterSpec(NONCE);
//        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
//
//        byte[] decrypted;
//        try {
//            decrypted = cipher.doFinal(Arrays.stream(encrypted.replace("[", "").replace("]", "").split(", "))
//                    .map(Byte::parseByte)
//                    .mapToByte(Byte::byteValue)
//                    .toArray());
//        } catch (IllegalBlockSizeException | BadPaddingException e) {
//            e.printStackTrace();
//            return null;
//        }
//
//        return new String(decrypted, StandardCharsets.UTF_8);
//    }
//
//    public static void main(String[] args) {
//        String originalText = "Hello, World!";
//
//        try {
//            String encryptedText = encrypt(originalText);
//            System.out.println("Encrypted Text: " + encryptedText);
//
//            String decryptedText = decrypt(encryptedText);
//            System.out.println("Decrypted Text: " + decryptedText);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}