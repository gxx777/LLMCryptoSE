import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class AsymmetricEncryption1 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public AsymmetricEncryption1() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encryptSymmetricKey(SecretKey symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedSymmetricKey);
    }

    public SecretKey decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(encryptedSymmetricKey);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKey = cipher.doFinal(bytes);
        return new SecretKeySpec(decryptedSymmetricKey, "AES"); // Assuming AES symmetric key
    }

    public static void main(String[] args) throws Exception {
        AsymmetricEncryption1 aes = new AsymmetricEncryption1();

        // Generate a symmetric key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey symmetricKey = keyGenerator.generateKey();

        // Encrypt the symmetric key with the public key
        String encryptedSymmetricKey = aes.encryptSymmetricKey(symmetricKey);
        System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

        // Decrypt the symmetric key with the private key
        SecretKey decryptedSymmetricKey = aes.decryptSymmetricKey(encryptedSymmetricKey);
        System.out.println("Decrypted Symmetric Key: " + Base64.getEncoder().encodeToString(decryptedSymmetricKey.getEncoded()));
    }
}