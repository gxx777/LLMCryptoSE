import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class AsymmetricEncryption4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption4(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * 使用公钥加密对称密钥。
     *
     * @param symmetricKey 要加密的对称密钥
     * @return 加密后的对称密钥
     * @throws Exception 如果加密失败
     */
    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    /**
     * 使用私钥解密对称密钥。
     *
     * @param encryptedSymmetricKey 加密后的对称密钥
     * @return 解密后的对称密钥
     * @throws Exception 如果解密失败
     */
    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    /**
     * 创建一个新的AES对称密钥并返回其字节表示形式。
     *
     * @return AES对称密钥的字节表示形式
     * @throws NoSuchAlgorithmException 如果AES密钥生成器不可用
     */
    public byte[] generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * 将对称密钥保存到文件中。
     *
     * @param symmetricKey 要保存的对称密钥
     * @param filePath 文件路径
     * @throws IOException 如果写入文件失败
     */
    public void saveSymmetricKeyToFile(byte[] symmetricKey, String filePath) throws IOException {
        Files.write(Paths.get(filePath), symmetricKey);
    }

    /**
     * 从文件中加载对称密钥。
     *
     * @param filePath 文件路径
     * @return 加载的对称密钥
     * @throws IOException 如果读取文件失败
     */
    public byte[] loadSymmetricKeyFromFile(String filePath) throws IOException {
        return Files.readAllBytes(Paths.get(filePath));
    }

    // 示例用法
    public static void main(String[] args) throws Exception {
        // 假定你已经有了一个密钥对
        KeyPair keyPair = generateKeyPair();

        // 实例化AsymmetricEncryption4类
        AsymmetricEncryption4 aes4 = new AsymmetricEncryption4(keyPair.getPrivate(), keyPair.getPublic());

        // 生成一个对称密钥
        byte[] symmetricKey = aes4.generateSymmetricKey();

        // 加密对称密钥
        byte[] encryptedSymmetricKey = aes4.encryptSymmetricKey(symmetricKey);

        // 将加密后的对称密钥保存到文件
        aes4.saveSymmetricKeyToFile(encryptedSymmetricKey, "encrypted_symmetric_key.bin");

        // 从文件加载加密的对称密钥
        byte[] loadedEncryptedSymmetricKey = aes4.loadSymmetricKeyFromFile("encrypted_symmetric_key.bin");

        // 解密对称密钥
        byte[] decryptedSymmetricKey = aes4.decryptSymmetricKey(loadedEncryptedSymmetricKey);

        // 验证对称密钥是否正确恢复
        System.out.println("Original Symmetric Key: " + new String(symmetricKey));
        System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));
    }

    // 辅助方法：生成RSA密钥对
    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}