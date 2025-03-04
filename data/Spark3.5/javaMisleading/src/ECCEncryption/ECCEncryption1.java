import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class ECCEncryption1 {
    private static final String ALGORITHM = "EC";
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;

    public static void main(String[] args) throws Exception {
        // 生成ECC密钥对
        KeyPair keyPair = generateECCKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 生成AES密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        SecretKey secretKey = keyGenerator.generateKey();

        // 使用ECC公钥加密AES密钥
        byte[] encryptedKey = encryptWithECC(secretKey.getEncoded(), publicKey);

        // 使用ECC私钥解密AES密钥
        byte[] decryptedKey = decryptWithECC(encryptedKey, privateKey);

        // 检查解密后的AES密钥是否与原始密钥相同
        if (Arrays.equals(secretKey.getEncoded(), decryptedKey)) {
            System.out.println("ECC encryption and decryption with AES key succeeded.");
        } else {
            System.out.println("ECC encryption and decryption with AES key failed.");
        }
    }

    private static KeyPair generateECCKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encryptWithECC(byte[] data, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private static byte[] decryptWithECC(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }
}