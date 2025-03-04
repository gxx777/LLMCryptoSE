import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ECCEncryption3 {
    private static final String ALGORITHM = "EC";
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final int SYMMETRIC_KEY_SIZE = 128;

    public static void main(String[] args) throws Exception {
        // 生成ECC密钥对
        KeyPair eccKeyPair = generateECCKeyPair();
        PublicKey eccPublicKey = eccKeyPair.getPublic();
        PrivateKey eccPrivateKey = eccKeyPair.getPrivate();

        // 生成对称密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
        keyGenerator.init(SYMMETRIC_KEY_SIZE);
        SecretKey symmetricKey = keyGenerator.generateKey();

        // 使用ECC公钥加密对称密钥
        byte[] encryptedSymmetricKey = encryptWithECC(symmetricKey, eccPublicKey);

        // 使用ECC私钥解密对称密钥
        SecretKey decryptedSymmetricKey = decryptWithECC(encryptedSymmetricKey, eccPrivateKey);

        // 检查解密后的对称密钥是否与原始对称密钥相同
        if (Arrays.equals(symmetricKey.getEncoded(), decryptedSymmetricKey.getEncoded())) {
            System.out.println("解密成功");
        } else {
            System.out.println("解密失败");
        }
    }

    private static KeyPair generateECCKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encryptWithECC(SecretKey symmetricKey, PublicKey eccPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, eccPublicKey);
        return cipher.doFinal(symmetricKey.getEncoded());
    }

    private static SecretKey decryptWithECC(byte[] encryptedSymmetricKey, PrivateKey eccPrivateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, eccPrivateKey);
        byte[] decryptedSymmetricKeyBytes = cipher.doFinal(encryptedSymmetricKey);
        return new SecretKeySpec(decryptedSymmetricKeyBytes, SYMMETRIC_ALGORITHM);
    }
}