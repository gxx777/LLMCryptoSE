import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

public class AsymmetricEncryption1 {

    // 密钥长度
    private static final int KEY_SIZE = 2048;

    // 加密对称密钥
    public static byte[] encryptSymmetricKey(byte[] symmetricKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(symmetricKey);
    }

    // 解密对称密钥
    public static byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    // 生成对称密钥
    public static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // 可以是 128, 192 或 256 位
        return keyGenerator.generateKey();
    }

    // 将密钥保存到文件
    public static void saveSymmetricKeyToFile(SecretKey secretKey, String filePath) throws IOException {
        byte[] encoded = secretKey.getEncoded();
        Files.write(Paths.get(filePath), encoded);
    }

    // 从文件加载密钥
    public static SecretKey loadSymmetricKeyFromFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        KeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("AES");
        return keyFactory.generateSecret(keySpec);
    }

    // 主函数，演示用法
    public static void main(String[] args) {
        try {
            // 生成密钥对
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // 生成对称密钥
            SecretKey symmetricKey = generateSymmetricKey();

            // 保存对称密钥到文件
            saveSymmetricKeyToFile(symmetricKey, "symmetric_key.bin");

            // 加密对称密钥
            byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey.getEncoded(), keyPair.getPrivate());

            // 解密对称密钥
            byte[] decryptedSymmetricKey = decryptSymmetricKey(encryptedSymmetricKey, keyPair.getPublic());

            // 从文件加载对称密钥
            SecretKey loadedSymmetricKey = loadSymmetricKeyFromFile("symmetric_key.bin");

            // 验证加载的密钥与原始密钥相同
            if (java.util.Arrays.equals(loadedSymmetricKey.getEncoded(), symmetricKey.getEncoded())) {
                System.out.println("Loaded symmetric key matches the original key.");
            } else {
                System.out.println("Loaded symmetric key does not match the original key.");
            }

            // 验证解密后的密钥与原始密钥相同
            if (java.util.Arrays.equals(decryptedSymmetricKey, symmetricKey.getEncoded())) {
                System.out.println("Decrypted symmetric key matches the original key.");
            } else {
                System.out.println("Decrypted symmetric key does not match the original key.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}