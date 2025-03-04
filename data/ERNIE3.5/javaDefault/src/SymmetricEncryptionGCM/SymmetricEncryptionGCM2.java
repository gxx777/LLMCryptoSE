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
//    private static final int TAG_LENGTH = 128;
//    private static final int KEY_LENGTH = 256;
//
//    private SecretKey key;
//    private GCMParameterSpec gcmParameterSpec;
//
//    public SymmetricEncryptionGCM2() throws NoSuchAlgorithmException {
//        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//        keyGenerator.init(KEY_LENGTH);
//        this.key = keyGenerator.generateKey();
//
//        this.gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, key.getEncoded().length * 8);
//    }
//
//    public String encrypt(String data) throws Exception {
//        Cipher cipher = Cipher.getInstance(ALGORITHM);
//        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
//
//        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
//        byte[] result = new byte[cipher.getOutputSize(data.getBytes(StandardCharsets.UTF_8))];
//
//        System.arraycopy(cipher.getIV(), 0, result, 0, cipher.getIV().length);
//        System.arraycopy(encrypted, 0, result, cipher.getIV().length, encrypted.length);
//
//        return Base64.getEncoder().encodeToString(result);
//    }
//
//    public String decrypt(String encryptedData) throws Exception {
//        byte[] decoded = Base64.getDecoder().decode(encryptedData);
//        Cipher  cipher = Cipher.getInstance(ALGORITHM);
//        byte[] iv = new byte[cipher.getBlockSize()];
//        byte[] cipherText = new byte[decoded.length - iv.length];
//
//        System.arraycopy(decoded, 0, iv, 0, iv.length);
//        System.arraycopy(decoded, iv.length, cipherText, 0, cipherText.length);
//        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH, iv));
//
//        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
//    }
//
//    public static void main(String[] args) {
//        try {
//            SymmetricEncryptionGCM2 encryptor = new SymmetricEncryptionGCM2();
//
//            String originalText = "Hello, World!";
//            String encryptedText = encryptor.encrypt(originalText);
//            String decryptedText = encryptor.decrypt(encryptedText);
//
//            System.out.println("Original Text: " + originalText);
//            System.out.println("Encrypted Text: " + encryptedText);
//            System.out.println("Decrypted Text: " + decryptedText);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}