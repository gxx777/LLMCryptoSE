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
//    private static final int TAG_LENGTH = 128; // GCM的认证标签长度，以位为单位
//    private static final int KEY_SIZE = 256; // 密钥大小，以位为单位
//
//    private SecretKey secretKey;
//
//    // 生成新的AES密钥
//    public SymmetricEncryptionGCM2() throws NoSuchAlgorithmException {
//        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//        keyGenerator.init(KEY_SIZE);
//        secretKey = keyGenerator.generateKey();
//    }
//
//    // 加密字符串
//    public String encrypt(String plainText) throws Exception {
//        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, secretKey.getEncoded().length * 8);
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
//
//        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
//        byte[] authTag = cipher.getIV(); // GCM的认证标签通常与初始化向量（IV）一起返回
//
//        // 将密文和认证标签组合在一起
//        byte[] combined = new byte[cipherText.length + authTag.length];
//        System.arraycopy(cipherText, 0, combined, 0, cipherText.length);
//        System.arraycopy(authTag, 0, combined, cipherText.length, authTag.length);
//
//        return Base64.getEncoder().encodeToString(combined);
//    }
//
//    // 解密字符串
//    public String decrypt(String encryptedText) throws Exception {
//        byte[] combined = Base64.getDecoder().decode(encryptedText);
//        byte[] cipherText = new byte[combined.length - secretKey.getEncoded().length];
//        byte[] authTag = new byte[secretKey.getEncoded().length];
//
//        System.arraycopy(combined, 0, cipherText, 0, cipherText.length);
//        System.arraycopy(combined, cipherText.length, authTag, 0, authTag.length);
//
//        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
//        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH, secretKey.getEncoded().length * 8, authTag);
//        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
//
//        return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
//    }
//
//    // 获取密钥（用于测试目的，生产环境中应避免公开密钥）
//    public SecretKey getSecretKey() {
//        return secretKey;
//    }
//
//    public static void main(String[] args) {
//        try {
//            SymmetricEncryptionGCM2 encryptor = new SymmetricEncryptionGCM2();
//
//            String originalText = "This is a secret message.";
//            String encryptedText = encryptor.encrypt(originalText);
//            System.out.println("Encrypted Text: " + encryptedText);
//
//            String decryptedText = encryptor.decrypt(encryptedText);
//            System.out.println("Decrypted Text: " + decryptedText);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}