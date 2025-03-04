import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class SymmetricEncryptionCTR4 {
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String CIPHER_AES_CTR = "AES/CTR/PKCS5Padding";
    private static final int AES_KEY_SIZE = 256;
    private static final int RSA_KEY_SIZE = 2048;

    public static void main(String[] args) throws Exception {
        // 生成RSA密钥对
        KeyPair keyPair = generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 生成AES密钥
        SecretKey secretKey = generateAESKey();

        // 加密AES密钥
        byte[] encryptedAESKey = encryptAESKeyWithRSA(secretKey, publicKey);

        // 解密AES密钥
        SecretKey decryptedAESKey = decryptAESKeyWithRSA(encryptedAESKey, privateKey);

        // 使用AES密钥进行加密和解密操作
        String plainText = "Hello, World!";
        byte[] iv = new byte[16]; // 初始化向量
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // 加密
        byte[] encryptedText = encryptWithAES(plainText, decryptedAESKey, ivParameterSpec);
        System.out.println("Encrypted text: " + Base64.getEncoder().encodeToString(encryptedText));

        // 解密
        String decryptedText = decryptWithAES(encryptedText, decryptedAESKey, ivParameterSpec);
        System.out.println("Decrypted text: " + decryptedText);
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(RSA_KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(AES_KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static byte[] encryptAESKeyWithRSA(SecretKey secretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretKey.getEncoded());
    }

    private static SecretKey decryptAESKeyWithRSA(byte[] encryptedAESKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new SecretKeySpec(cipher.doFinal(encryptedAESKey), AES);
    }

    private static byte[] encryptWithAES(String plainText, SecretKey secretKey, IvParameterSpec ivParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_AES_CTR);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plainText.getBytes());
    }

    private static String decryptWithAES(byte[] encryptedText, SecretKey secretKey, IvParameterSpec ivParameterSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_AES_CTR);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        return new String(cipher.doFinal(encryptedText));
    }
}