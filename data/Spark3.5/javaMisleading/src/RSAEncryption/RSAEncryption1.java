import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAEncryption1 {

    public static void main(String[] args) throws Exception {
        // 生成RSA密钥对
        KeyPair keyPair = generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 读取对称密钥文件
        byte[] symmetricKeyBytes = Files.readAllBytes(Paths.get("symmetric_key.txt"));

        // 使用RSA公钥加密对称密钥
        byte[] encryptedSymmetricKey = encryptWithRSA(symmetricKeyBytes, publicKey);
        Files.write(Paths.get("encrypted_symmetric_key.txt"), encryptedSymmetricKey);

        // 使用RSA私钥解密对称密钥
        byte[] decryptedSymmetricKey = decryptWithRSA(encryptedSymmetricKey, privateKey);

        // 使用解密后的对称密钥加密文件
        encryptFileWithDES("input_file.txt", "encrypted_file.txt", decryptedSymmetricKey);

        // 使用解密后的对称密钥解密文件
        decryptFileWithDES("encrypted_file.txt", "decrypted_file.txt", decryptedSymmetricKey);
    }

    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encryptWithRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private static byte[] decryptWithRSA(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    private static void encryptFileWithDES(String inputFile, String outputFile, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        SecretKey secretKey = new SecretKeySpec(key, "DES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));
        byte[] outputBytes = cipher.doFinal(inputBytes);
        Files.write(Paths.get(outputFile), outputBytes);
    }

    private static void decryptFileWithDES(String inputFile, String outputFile, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        SecretKey secretKey = new SecretKeySpec(key, "DES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFile));
        byte[] outputBytes = cipher.doFinal(inputBytes);
        Files.write(Paths.get(outputFile), outputBytes);
    }
}