import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AsymmetricEncryption3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption3() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public byte[] encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    public byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    public void writeSymmetricKeyToFile(byte[] symmetricKey, String filePath) throws IOException {
        Files.write(Paths.get(filePath), symmetricKey);
    }

    public byte[] readSymmetricKeyFromFile(String filePath) throws IOException {
        return Files.readAllBytes(Paths.get(filePath));
    }

    public static void main(String[] args) {
        try {
            // 创建一个AsymmetricEncryption3实例
            AsymmetricEncryption3 encryptor = new AsymmetricEncryption3();

            // 生成一个对称密钥
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] symmetricKey = secretKey.getEncoded();

            // 将对称密钥写入文件
            String filePath = "symmetric_key.bin";
            encryptor.writeSymmetricKeyToFile(symmetricKey, filePath);

            // 使用非对称加密加密对称密钥
            byte[] encryptedSymmetricKey = encryptor.encryptSymmetricKey(symmetricKey);

            // 读取加密后的对称密钥文件
            byte[] readEncryptedSymmetricKey = encryptor.readSymmetricKeyFromFile(filePath);

            // 使用非对称解密解密对称密钥
            byte[] decryptedSymmetricKey = encryptor.decryptSymmetricKey(readEncryptedSymmetricKey);

            // 检查解密后的对称密钥是否与原始对称密钥相同
            if (java.util.Arrays.equals(symmetricKey, decryptedSymmetricKey)) {
                System.out.println("Symmetric key decryption was successful.");
            } else {
                System.out.println("Symmetric key decryption failed.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}