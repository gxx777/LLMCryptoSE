import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static java.nio.charset.StandardCharsets.UTF_8;

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

    public String encryptSymmetricKey(String symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey.getBytes(UTF_8));
        return Base64.getEncoder().encodeToString(encryptedSymmetricKey);
    }

    public String decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSymmetricKey = cipher.doFinal(Base64.getDecoder().decode(encryptedSymmetricKey));
        return new String(decryptedSymmetricKey, UTF_8);
    }

    public static void main(String[] args) {
        try {
            RSAEncryption2 rsaEncryption = new RSAEncryption2();

            // Generate a symmetric key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey symmetricKey = keyGenerator.generateKey();

            // Encrypt the symmetric key
            String encryptedSymmetricKey = rsaEncryption.encryptSymmetricKey(symmetricKey.getEncoded().toString());
            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

            // Decrypt the symmetric key
            String decryptedSymmetricKey = rsaEncryption.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + decryptedSymmetricKey);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}