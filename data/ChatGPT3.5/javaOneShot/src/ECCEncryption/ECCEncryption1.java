import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import java.util.Base64;

public class ECCEncryption1 {
    
    public static void main(String[] args) {
        try {
            // 生成ECC密钥对
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            
            // 保存公钥和私钥到文件
            saveKeyToFile("publicKey.txt", publicKey.getEncoded());
            saveKeyToFile("privateKey.txt", privateKey.getEncoded());
            
            // 生成对称密钥
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey secretKey = keyGenerator.generateKey();
            
            // 使用公钥加密对称密钥
            Cipher cipher = Cipher.getInstance("ECIES");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedKey = cipher.doFinal(secretKey.getEncoded());
            
            // 使用私钥解密对称密钥
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedKey = cipher.doFinal(encryptedKey);
            
            // 输出解密后的对称密钥
            System.out.println("Decrypted Key: " + Base64.getEncoder().encodeToString(decryptedKey));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void saveKeyToFile(String fileName, byte[] keyData) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(keyData);
        }
    }
}