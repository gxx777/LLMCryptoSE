import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ECCEncryption1 {

    public static void main(String[] args) throws Exception {
        // 生成ECC密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 生成对称密钥（例如AES）
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] symmetricKeyBytes = secretKey.getEncoded();

        // 加密对称密钥
        Cipher encryptCipher = Cipher.getInstance("ECIES");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = encryptCipher.doFinal(symmetricKeyBytes);

        // 将加密的对称密钥写入文件
        File encryptedKeyFile = new File("encrypted_symmetric_key.bin");
        Files.write(encryptedKeyFile.toPath(), encryptedSymmetricKey);

        // 从文件中读取加密的对称密钥
        byte[] readEncryptedSymmetricKey = Files.readAllBytes(encryptedKeyFile.toPath());

        // 解密对称密钥
        Cipher decryptCipher = Cipher.getInstance("ECIES");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKey = decryptCipher.doFinal(readEncryptedSymmetricKey);

        // 验证解密后的对称密钥是否与原始密钥相同
        if (java.util.Arrays.equals(symmetricKeyBytes, decryptedSymmetricKey)) {
            System.out.println("Symmetric key decrypted successfully!");
        } else {
            System.out.println("Error: Decrypted symmetric key does not match the original key.");
        }
    }
}