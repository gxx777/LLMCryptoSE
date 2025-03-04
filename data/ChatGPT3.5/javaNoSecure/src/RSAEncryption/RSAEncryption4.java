import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAEncryption4 {
    
    public static void encryptFile(String inputFile, String outputFile, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        try (FileInputStream in = new FileInputStream(inputFile);
             FileOutputStream out = new FileOutputStream(outputFile)) {
            byte[] input = new byte[117];
            int bytesRead;
            while ((bytesRead = in.read(input)) != -1) {
                byte[] output = cipher.doFinal(input, 0, bytesRead);
                out.write(output);
            }
        }
    }
    
    public static void decryptFile(String inputFile, String outputFile, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        try (FileInputStream in = new FileInputStream(inputFile);
             FileOutputStream out = new FileOutputStream(outputFile)) {
            byte[] input = new byte[128];
            int bytesRead;
            while ((bytesRead = in.read(input)) != -1) {
                byte[] output = cipher.doFinal(input, 0, bytesRead);
                out.write(output);
            }
        }
    }
    
    public static PublicKey getPublicKey(byte[] keyBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
    
    public static PrivateKey getPrivateKey(byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }
    
    public static void main(String[] args) {
        try {
            // 读取对称密钥文件
            byte[] keyBytes = "".getBytes();// 读取对称密钥文件的字节数组
            
            // 读取公钥文件
            byte[] publicKeyBytes = "".getBytes();/* 读取公钥文件的字节数组 */;
            PublicKey publicKey = getPublicKey(publicKeyBytes);
            
            // 读取私钥文件
            byte[] privateKeyBytes = "".getBytes();/* 读取私钥文件的字节数组 */
            PrivateKey privateKey = getPrivateKey(privateKeyBytes);
            
            // 加密对称密钥文件
            encryptFile("symmetric_key.txt", "encrypted_key.txt", publicKey);
            
            // 解密对称密钥文件
            decryptFile("encrypted_key.txt", "decrypted_key.txt", privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}