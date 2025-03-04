//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.jce.spec.ECParameterSpec;
//import org.bouncycastle.math.ec.ECPoint;
//import org.bouncycastle.math.ec.ECCurve;
//
//
//import javax.crypto.*;
//import javax.crypto.spec.SecretKeySpec;
//import java.security.*;
//import java.security.spec.InvalidKeySpecException;
//import java.security.spec.X509EncodedKeySpec;
//import java.util.Arrays;
//
//public class ECCEncryption4 {
//    private static final String ALGORITHM = "ECDH";
//    private static final String CIPHER_ALGORITHM = "AES";
//    private static final int KEY_SIZE = 128;
//
//    static {
//        Security.addProvider(new BouncyCastleProvider());
//    }
//
//    public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
//        KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM);
//        keyAgreement.init(privateKey);
//        keyAgreement.doPhase(publicKey, true);
//        return keyAgreement.generateSecret(CIPHER_ALGORITHM);
//    }
//
//    public static byte[] encrypt(byte[] data, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//        return cipher.doFinal(data);
//    }
//
//    public static byte[] decrypt(byte[] data, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
//        cipher.init(Cipher.DECRYPT_MODE, secretKey);
//        return cipher.doFinal(data);
//    }
//
//    public static void main(String[] args) throws Exception {
//        // 生成ECC密钥对
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
//        keyPairGenerator.initialize(new ECParameterSpec(ECCurve.P_256.getCurve(), new ECPoint.Fp(ECCurve.P_256.getCurve(), null, null), new BigInteger("1"), 1));
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        PrivateKey privateKey = keyPair.getPrivate();
//        PublicKey publicKey = keyPair.getPublic();
//
//        // 生成对称密钥
//        SecretKey secretKey = KeyGenerator.getInstance(CIPHER_ALGORITHM).generateKey();
//
//        // 使用ECC密钥对生成共享密钥
//        SecretKey sharedSecret = generateSharedSecret(privateKey, publicKey);
//
//        // 使用共享密钥加密数据
//        byte[] encryptedData = encrypt("Hello, World!".getBytes(), sharedSecret);
//        System.out.println("Encrypted data: " + Arrays.toString(encryptedData));
//
//        // 使用共享密钥解密数据
//        byte[] decryptedData = decrypt(encryptedData, sharedSecret);
//        System.out.println("Decrypted data: " + new String(decryptedData));
//    }
//}