import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class RSAEncryption3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAEncryption3() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // 使用2048位密钥长度
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public String encryptSymmetricKey(SecretKey symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(symmetricKey.getEncoded());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public SecretKey decryptSymmetricKey(String encryptedKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));
        return new SecretKeySpec(decrypted, "AES"); // 假设对称密钥是AES类型的
    }

    public static void main(String[] args) {
        try {
            RSAEncryption3 rsaEncryption = new RSAEncryption3();

            // 生成一个对称密钥（例如AES）
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128); // 使用128位AES密钥
            SecretKey symmetricKey = keyGenerator.generateKey();

            // 加密对称密钥
            String encryptedSymmetricKey = rsaEncryption.encryptSymmetricKey(symmetricKey);
            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

            // 解密对称密钥
            SecretKey decryptedSymmetricKey = rsaEncryption.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + decryptedSymmetricKey.getEncoded().length);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}