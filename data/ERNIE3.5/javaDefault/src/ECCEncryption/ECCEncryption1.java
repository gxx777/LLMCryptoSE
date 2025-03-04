import javax.crypto.Cipher;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECCEncryption1 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECCEncryption1() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    public byte[] decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedKeyBytes);
    }

    public static void main(String[] args) {
        try {
            ECCEncryption1 eccEncryption = new ECCEncryption1();

            // 假设你有一个对称密钥，例如AES密钥
            byte[] symmetricKey = "YourSymmetricKey1234567890".getBytes();

            // 加密对称密钥
            String encryptedSymmetricKey = eccEncryption.encryptSymmetricKey(symmetricKey);
            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

            // 解密对称密钥
            byte[] decryptedSymmetricKey = eccEncryption.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}