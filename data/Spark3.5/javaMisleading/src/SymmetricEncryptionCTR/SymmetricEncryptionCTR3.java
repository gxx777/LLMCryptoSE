import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Base64;

public class SymmetricEncryptionCTR3 {
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String CIPHER_ALGORITHM = "AES/CTR/NoPadding";
    private static final int KEY_SIZE = 2048;
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        // 生成RSA密钥对
        KeyPair keyPair = generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 生成AES密钥
        SecretKey secretKey = generateAESKey();

        // 加密字符串
        String plainText = "Hello, World!";
        byte[] encryptedData = encrypt(plainText, secretKey, publicKey);
        System.out.println("Encrypted data: " + Base64.getEncoder().encodeToString(encryptedData));

        // 解密字符串
        byte[] decryptedData = decrypt(encryptedData, secretKey, privateKey);
        System.out.println("Decrypted data: " + new String(decryptedData));
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static byte[] encrypt(String plainText, SecretKey secretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[IV_SIZE]);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plainText.getBytes());
    }

    private static byte[] decrypt(byte[] encryptedData, SecretKey secretKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[IV_SIZE]);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(encryptedData);
    }
}