import java.security.*;
import javax.crypto.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class AsymmetricEncryption2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption2() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public String encryptSymmetricKey(String symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encrypted = cipher.doFinal(symmetricKey.getBytes(UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decoded = Base64.getDecoder().decode(encryptedSymmetricKey);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, UTF_8);
    }

    public static void main(String[] args) {
        try {
            AsymmetricEncryption2 aes = new AsymmetricEncryption2();

            // 假设我们有一个对称密钥
            String symmetricKey = "ThisIsASymmetricKey";

            // 使用公钥加密对称密钥
            String encryptedSymmetricKey = aes.encryptSymmetricKey(symmetricKey);
            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

            // 使用私钥解密对称密钥
            String decryptedSymmetricKey = aes.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + decryptedSymmetricKey);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}