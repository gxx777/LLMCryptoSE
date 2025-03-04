import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ECCEncryption2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 生成ECC密钥对
    public ECCEncryption2() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyGen.initialize(ecSpec, new SecureRandom());
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    // 使用公钥加密对称密钥
    public String encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // 使用私钥解密对称密钥
    public byte[] decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        byte[] cipherText = Base64.getDecoder().decode(encryptedSymmetricKey);
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(cipherText);
    }

    // 测试方法
    public static void main(String[] args) throws Exception {
        ECCEncryption2 eccEncryption = new ECCEncryption2();

        // 假设我们有一个对称密钥
        byte[] symmetricKey = "ThisIsASymmetricKey".getBytes();

        // 加密对称密钥
        String encryptedSymmetricKey = eccEncryption.encryptSymmetricKey(symmetricKey);
        System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

        // 解密对称密钥
        byte[] decryptedSymmetricKey = eccEncryption.decryptSymmetricKey(encryptedSymmetricKey);
        System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));
    }
}