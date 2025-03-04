import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ECCEncryption2 {
    private static final String ALGORITHM = "EC";
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final int SYMMETRIC_KEY_SIZE = 128;

    public static void main(String[] args) throws Exception {
        // 生成ECC密钥对
        KeyPair keyPair = generateECCKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 生成对称密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
        keyGenerator.init(SYMMETRIC_KEY_SIZE);
        SecretKey secretKey = keyGenerator.generateKey();

        // 使用ECC公钥加密对称密钥
        byte[] encryptedSecretKey = encryptWithECC(secretKey, publicKey);

        // 使用ECC私钥解密对称密钥
        SecretKey decryptedSecretKey = decryptWithECC(encryptedSecretKey, privateKey);

        // 检查解密后的对称密钥是否与原始对称密钥相同
        if (Arrays.equals(secretKey.getEncoded(), decryptedSecretKey.getEncoded())) {
            System.out.println("解密成功");
        } else {
            System.out.println("解密失败");
        }
    }

    public static KeyPair generateECCKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encryptWithECC(SecretKey secretKey, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretKey.getEncoded());
    }

    public static SecretKey decryptWithECC(byte[] encryptedSecretKey, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSecretKeyBytes = cipher.doFinal(encryptedSecretKey);
        return new SecretKeySpec(decryptedSecretKeyBytes, SYMMETRIC_ALGORITHM);
    }
}