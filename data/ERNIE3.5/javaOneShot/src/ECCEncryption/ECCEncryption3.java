import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class ECCEncryption3 {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // 生成ECC密钥对
    public static KeyPair generateECCKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECNamedCurveGenParameterSpec("prime256v1")); // 使用指定的椭圆曲线
        return keyPairGenerator.generateKeyPair();
    }

    // 使用ECC公钥加密对称密钥
    public static String encryptSymmetricKeyWithECC(SecretKey symmetricKey, PublicKey eccPublicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, eccPublicKey);
        byte[] encryptedKey = cipher.doFinal(symmetricKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    // 使用ECC私钥解密对称密钥
    public static SecretKey decryptSymmetricKeyWithECC(String encryptedSymmetricKeyBase64, PrivateKey eccPrivateKey) throws Exception {
        byte[] encryptedKey = Base64.getDecoder().decode(encryptedSymmetricKeyBase64);
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, eccPrivateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decryptedKey, "AES"); // 假设对称密钥是AES密钥
    }

    public static void main(String[] args) throws Exception {
        // 生成ECC密钥对
        KeyPair eccKeyPair = generateECCKeyPair();
        PublicKey eccPublicKey = eccKeyPair.getPublic();
        PrivateKey eccPrivateKey = eccKeyPair.getPrivate();

        // 生成对称密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey symmetricKey = keyGenerator.generateKey();

        // 加密对称密钥
        String encryptedSymmetricKey = encryptSymmetricKeyWithECC(symmetricKey, eccPublicKey);
        System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

        // 解密对称密钥
        SecretKey decryptedSymmetricKey = decryptSymmetricKeyWithECC(encryptedSymmetricKey, eccPrivateKey);
        System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey.getEncoded()));
    }
}