import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.util.Arrays;
import java.util.Base64;

public class ECCEncryption1 {
    public static void main(String[] args) throws Exception {
        // 生成ECC密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 生成对称密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // 使用公钥加密对称密钥
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSecretKey = cipher.doFinal(secretKey.getEncoded());

        // 将加密后的对称密钥写入文件
        try (FileOutputStream fos = new FileOutputStream("encrypted_secret_key.txt")) {
            fos.write(encryptedSecretKey);
        }

        // 从文件中读取加密后的对称密钥
        byte[] encryptedSecretKeyFromFile;
        FileInputStream fis = new FileInputStream("encrypted_secret_key.txt");
        encryptedSecretKeyFromFile = new byte[fis.available()];
        int length = fis.read(encryptedSecretKeyFromFile);
        // 使用私钥解密对称密钥
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSecretKey = cipher.doFinal(encryptedSecretKeyFromFile);

        // 验证解密后的对称密钥是否与原始对称密钥相同
        if (Arrays.equals(secretKey.getEncoded(), decryptedSecretKey)) {
            System.out.println("解密成功");
        } else {
            System.out.println("解密失败");
        }
    }
}