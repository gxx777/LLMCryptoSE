import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class RSAEncryption2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAEncryption2() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encryptSymmetricKey(SecretKey symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKeyBytes = cipher.doFinal(symmetricKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKeyBytes);
    }

    public SecretKey decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKeyBytes);
        SecretKey symmetricKey = new SecretKeySpec(decryptedKeyBytes, "AES");
        return symmetricKey;
    }

    public static void main(String[] args) throws Exception {
        RSAEncryption2 rsaEncryption = new RSAEncryption2();

        // Generate a symmetric key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey symmetricKey = keyGenerator.generateKey();

        // Encrypt the symmetric key using RSA
        String encryptedSymmetricKey = rsaEncryption.encryptSymmetricKey(symmetricKey);
        System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

        // Decrypt the symmetric key using RSA
        SecretKey decryptedSymmetricKey = rsaEncryption.decryptSymmetricKey(encryptedSymmetricKey);
        System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey.getEncoded()));
    }
}