import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ECCEncryption3 {
    private static final String ALGORITHM = "ECDH";
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final String PROVIDER = "BC";
    private static final int KEY_SIZE = 256;
    private static final int BLOCK_SIZE = 128;

    public static void main(String[] args) throws Exception {
        // 生成ECC密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 生成对称密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM, PROVIDER);
        keyGenerator.init(KEY_SIZE);
        SecretKey secretKey = keyGenerator.generateKey();

        // 使用ECDH算法进行密钥协商
        KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM, PROVIDER);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // 使用共享密钥加密对称密钥
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sharedSecret, SYMMETRIC_ALGORITHM));
        byte[] encryptedSecretKey = cipher.doFinal(secretKey.getEncoded());

        // 使用共享密钥解密对称密钥
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sharedSecret, SYMMETRIC_ALGORITHM));
        byte[] decryptedSecretKey = cipher.doFinal(encryptedSecretKey);

        // 检查解密后的对称密钥是否与原始密钥相同
        if (MessageDigest.isEqual(secretKey.getEncoded(), decryptedSecretKey)) {
            System.out.println("ECC encryption and decryption using symmetric key succeeded.");
        } else {
            System.out.println("ECC encryption and decryption using symmetric key failed.");
        }
    }
}