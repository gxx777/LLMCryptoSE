import java.io.*;
import java.security.*;
import javax.crypto.*;
import java.util.Base64;

public class RSAEncryption2 {

    public static void main(String[] args) {
        try {
            // 生成RSA密钥对
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // 2048位密钥
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 生成对称密钥并保存至文件
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128); // 128位密钥
            SecretKey secretKey = keyGenerator.generateKey();
            writeKeyToFile(secretKey.getEncoded(), "symmetric_key.txt");

            // 使用RSA公钥加密对称密钥
            byte[] encryptedKey = encryptRSA(publicKey, secretKey.getEncoded());

            // 使用RSA私钥解密对称密钥
            byte[] decryptedKey = decryptRSA(privateKey, encryptedKey);

            // 读取对称密钥文件
            byte[] savedKey = readKeyFromFile("symmetric_key.txt");

            // 比较解密后的对称密钥和读取的密钥文件内容是否一致
            if (MessageDigest.isEqual(decryptedKey, savedKey)) {
                System.out.println("对称密钥加解密成功！");
            } else {
                System.out.println("对称密钥加解密失败！");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] encryptRSA(PublicKey publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSA(PrivateKey privateKey, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    public static void writeKeyToFile(byte[] key, String fileName) throws IOException {
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(key);
        fos.close();
    }

    public static byte[] readKeyFromFile(String fileName) throws IOException {
        FileInputStream fis = new FileInputStream(fileName);
        byte[] key = new byte[fis.available()];
        fis.read(key);
        fis.close();
        return key;
    }
}