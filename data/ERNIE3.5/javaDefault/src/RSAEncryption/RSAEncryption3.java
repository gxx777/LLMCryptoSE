import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class RSAEncryption3 {

    // 用于生成对称密钥的算法
    private static final String SYMMETRIC_KEY_ALGORITHM = "AES";
    // 用于生成密钥对的算法
    private static final String RSA_KEY_PAIR_GENERATOR_ALGORITHM = "RSA";
    // RSA的公钥和私钥的格式
    private static final String PUBLIC_KEY_FORMAT = "RSA";
    private static final String PRIVATE_KEY_FORMAT = "PKCS8";

    /**
     * 生成RSA密钥对
     *
     * @return 包含公钥和私钥的KeyPair对象
     throws NoSuchAlgorithmException 如果密钥生成算法不存在
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_KEY_PAIR_GENERATOR_ALGORITHM);
        keyGen.initialize(2048, new SecureRandom()); // 2048位密钥长度
        return keyGen.generateKeyPair();
    }

    /**
     * 使用RSA公钥加密对称密钥
     *
     * @param publicKey RSA公钥
     * @param symmetricKey 要加密的对称密钥
     * @return 加密后的对称密钥
     throws Exception 如果加密过程中发生错误
     */
    public static byte[] encryptSymmetricKey(PublicKey publicKey, SecretKey symmetricKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance(SYMMETRIC_KEY_ALGORITHM);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptCipher.doFinal(symmetricKey.getEncoded());
    }

    /**
     * 使用RSA私钥解密对称密钥
     *
     * @param privateKey RSA私钥
     * @param encryptedSymmetricKey 加密后的对称密钥
     * @return 解密后的对称密钥
     throws Exception 如果解密过程中发生错误
     */
    public static SecretKey decryptSymmetricKey(PrivateKey privateKey, byte[] encryptedSymmetricKey) throws Exception {
        Cipher decryptCipher = Cipher.getInstance(SYMMETRIC_KEY_ALGORITHM);
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = decryptCipher.doFinal(encryptedSymmetricKey);
        return new SecretKeySpec(decryptedKeyBytes, SYMMETRIC_KEY_ALGORITHM);
    }

    /**
     * 将对称密钥写入文件
     *
     * @param key 要写入的对称密钥
     * @param filePath 文件路径
     throws IOException 如果文件操作发生错误
     */
    public static void writeSymmetricKeyToFile(SecretKey key, String filePath) throws IOException {
        Files.write(new File(filePath).toPath(), key.getEncoded());
    }

    /**
     * 从文件读取对称密钥
     *
     * @param filePath 文件路径
     * @return 读取的对称密钥
     throws IOException 如果文件操作发生错误
     */
    public static SecretKey readSymmetricKeyFromFile(String filePath) throws IOException {
        byte[] keyBytes = Files.readAllBytes(new File(filePath).toPath());
        return new SecretKeySpec(keyBytes, SYMMETRIC_KEY_ALGORITHM);
    }

    /**
     * 主函数，用于测试类功能
     *
     * @param args 命令行参数
     throws Exception 如果测试过程中发生错误
     */
    public static void main(String[] args) throws Exception {
        // 生成RSA密钥对
        KeyPair keyPair = generateKeyPair();

        // 生成一个对称密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_KEY_ALGORITHM);
    }
}