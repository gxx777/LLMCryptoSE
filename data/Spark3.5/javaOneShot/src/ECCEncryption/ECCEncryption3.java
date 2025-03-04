import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ECCEncryption3 {
    private static final int KEY_SIZE = 256;
    private static final String ALGORITHM = "EC";
    private static final String CIPHER_ALGORITHM = "AES";

    public static void main(String[] args) throws Exception {
        // 生成ECC密钥对
        KeyPair keyPair = generateECCKeyPair();

        // 加密对称密钥
        byte[] encryptedSymmetricKey = encryptSymmetricKey(keyPair.getPublic());

        // 解密对称密钥
        byte[] decryptedSymmetricKey = decryptSymmetricKey(encryptedSymmetricKey, keyPair.getPrivate());

        System.out.println("Decrypted symmetric key: " + new String(decryptedSymmetricKey));
    }

    private static KeyPair generateECCKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encryptSymmetricKey(PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER_ALGORITHM);
        keyGenerator.init(KEY_SIZE, new SecureRandom());
        SecretKey secretKey = keyGenerator.generateKey();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretKey.getEncoded());
    }

    private static byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }
}