import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class RSAEncryption1 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAEncryption1() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encryptSymmetricKey(SecretKey symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(symmetricKey.getEncoded());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public SecretKey decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedSymmetricKey));
        return new SecretKeySpec(decrypted, "AES");
    }

    public static void main(String[] args) throws Exception {
        RSAEncryption1 rsaEncryption = new RSAEncryption1();

        // Generate a symmetric key (e.g., AES)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey aesKey = keyGenerator.generateKey();

        // Encrypt the symmetric key using RSA
        String encryptedAesKey = rsaEncryption.encryptSymmetricKey(aesKey);
        System.out.println("Encrypted AES Key: " + encryptedAesKey);

        // Decrypt the symmetric key using RSA
        SecretKey decryptedAesKey = rsaEncryption.decryptSymmetricKey(encryptedAesKey);
        System.out.println("Decrypted AES Key: " + new String(decryptedAesKey.getEncoded()));
    }
}