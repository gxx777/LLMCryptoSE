import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ECCEncryption4 {

    // ECC算法名称
    private static final String ECC_ALGORITHM = "EC";

    // 对称密钥算法名称
    private static final String SYMMETRIC_ALGORITHM = "AES";

    // 密钥长度
    private static final int KEY_SIZE = 256;

    // 生成ECC密钥对
    public static KeyPair generateECCKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ECC_ALGORITHM);
        keyPairGenerator.initialize(new ECGenParameterSpec("prime256v1")); // 使用特定的椭圆曲线参数
        return keyPairGenerator.generateKeyPair();
    }

    // 使用ECC公钥加密对称密钥
    public static byte[] encryptSymmetricKeyWithECC(PublicKey publicKey, SecretKey symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey.getEncoded());
    }

    // 使用ECC私钥解密对称密钥
    public static SecretKey decryptSymmetricKeyWithECC(PrivateKey privateKey, byte[] encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKeyBytes = cipher.doFinal(encryptedSymmetricKey);
        return new SecretKeySpec(decryptedSymmetricKeyBytes, SYMMETRIC_ALGORITHM);
    }

    // 将对称密钥写入文件
    public static void writeSymmetricKeyToFile(SecretKey symmetricKey, File file) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(symmetricKey.getEncoded());
        }
    }

    // 从文件读取对称密钥
    public static SecretKey readSymmetricKeyFromFile(File file) throws IOException {
        byte[] keyBytes = Files.readAllBytes(file.toPath());
        return new SecretKeySpec(keyBytes, SYMMETRIC_ALGORITHM);
    }

    // 示例用法
    public static void main(String[] args) throws Exception {
        // 生成ECC密钥对
        KeyPair eccKeyPair = generateECCKeyPair();
        PublicKey eccPublicKey = eccKeyPair.getPublic();
        PrivateKey eccPrivateKey = eccKeyPair.getPrivate();

        // 生成对称密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        SecretKey symmetricKey = keyGenerator.generateKey();

        // 将对称密钥写入文件
        File symmetricKeyFile = new File("symmetricKey.bin");
        writeSymmetricKeyToFile(symmetricKey, symmetricKeyFile);

        // 使用ECC公钥加密对称密钥
        byte[] encryptedSymmetricKey = encryptSymmetricKeyWithECC(eccPublicKey, symmetricKey);

        // 读取加密的对称密钥文件
        File encryptedSymmetricKeyFile = new File("encryptedSymmetricKey.bin");
        Files.write(encryptedSymmetricKeyFile.toPath(), encryptedSymmetricKey);

        // 使用ECC私钥解密对称密钥
        SecretKey decryptedSymmetricKey = decryptSymmetricKeyWithECC(eccPrivateKey, Files.readAllBytes(encryptedSymmetricKeyFile.toPath()));

        // 验证解密后的对称密钥是否与原始密钥相同
        if (symmetricKey.getEncoded().equals(decryptedSymmetricKey.getEncoded())) {
            System.out.println("Symmetric key decryption was successful.");
        } else {
            System.out.println("Symmetric key decryption failed.");
        }
    }
}