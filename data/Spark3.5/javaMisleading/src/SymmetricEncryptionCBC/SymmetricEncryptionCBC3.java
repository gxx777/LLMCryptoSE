import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class SymmetricEncryptionCBC3 {
    private static final String ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 128;

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        // 原始数据
        String data = "Hello, World!";

        // 加密
        String encryptedData = encrypt(data, publicKey);
        System.out.println("加密后的数据： " + encryptedData);

        // 解密
        String decryptedData = decrypt(encryptedData, keyPair.getPrivate());
        System.out.println("解密后的数据： " + decryptedData);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    public static String encrypt(String data, PublicKey publicKey) throws Exception {
        // 生成AES密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        SecretKey secretKey = keyGenerator.generateKey();

        // 初始化Cipher对象
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, new IvParameterSpec(new byte[16]));

        // 加密数据
        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        // 返回加密后的数据（包括AES密钥和加密后的数据）
        return Base64.getEncoder().encodeToString(secretKey.getEncoded()) + "|" + Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decrypt(String encryptedData, PrivateKey privateKey) throws Exception {
        // 分割加密后的数据（包括AES密钥和加密后的数据）
        String[] parts = encryptedData.split("\\|");
        byte[] encryptedTextBytes = Base64.getDecoder().decode(parts[1]);

        // 初始化Cipher对象
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, new IvParameterSpec(new byte[16]));

        // 解密数据
        byte[] decryptedData = cipher.doFinal(encryptedTextBytes);

        // 返回解密后的数据
        return new String(decryptedData, StandardCharsets.UTF_8);
    }
}