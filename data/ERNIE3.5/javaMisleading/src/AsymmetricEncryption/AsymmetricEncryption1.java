import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class AsymmetricEncryption1 {

    // 生成RSA密钥对
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    // 使用RSA公钥加密AES密钥
    public static byte[] encryptAESKeyWithRSA(PublicKey publicKey, byte[] aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(aesKey);
    }

    // 使用RSA私钥解密AES密钥
    public static byte[] decryptAESKeyWithRSA(PrivateKey privateKey, byte[] encryptedAESKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedAESKey);
    }

    // 使用AES密钥加密数据
    public static byte[] encryptDataWithAES(byte[] aesKey, byte[] data) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }

    // 使用AES密钥解密数据
    public static byte[] decryptDataWithAES(byte[] aesKey, byte[] encryptedData) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) throws Exception {
        // 生成RSA密钥对
        KeyPair keyPair = generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 生成AES密钥
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(128);
        SecretKey aesKey = aesKeyGen.generateKey();

        // 使用RSA公钥加密AES密钥
        byte[] encryptedAESKey = encryptAESKeyWithRSA(publicKey, aesKey.getEncoded());

        // 模拟存储加密的AES密钥
        File aesKeyFile = new File("encrypted_aes_key.bin");
        try (FileOutputStream fos = new FileOutputStream(aesKeyFile)) {
            fos.write(encryptedAESKey);
        }

        // 从文件中读取加密的AES密钥
        byte[] readEncryptedAESKey = Files.readAllBytes(Paths.get("encrypted_aes_key.bin"));

        // 使用RSA私钥解密AES密钥
        byte[] decryptedAESKey = decryptAESKeyWithRSA(privateKey, readEncryptedAESKey);

        // 使用AES密钥加密数据
        String originalData = "Hello, World!";
        byte[] encryptedData = encryptDataWithAES(decryptedAESKey, originalData.getBytes());

        // 使用AES密钥解密数据
        byte[] decryptedData = decryptDataWithAES(decryptedAESKey, encryptedData);

        System.out.println(new String(decryptedData));  // 输出：Hello, World!
    }
}