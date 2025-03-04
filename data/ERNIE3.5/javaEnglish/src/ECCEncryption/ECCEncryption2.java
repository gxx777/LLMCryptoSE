import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class ECCEncryption2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECCEncryption2() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encryptSymmetricKey(String symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(symmetricKey.getBytes(UTF_8));
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    public String decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(Base64.getDecoder().decode(encryptedSymmetricKey));
        return new String(decryptedKey, UTF_8);
    }

    public static void main(String[] args) throws Exception {
        ECCEncryption2 eccEncryption = new ECCEncryption2();

        String symmetricKey = "mySymmetricKey123";

        // Encrypt the symmetric key
        String encryptedSymmetricKey = eccEncryption.encryptSymmetricKey(symmetricKey);
        System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

        // Decrypt the symmetric key
        String decryptedSymmetricKey = eccEncryption.decryptSymmetricKey(encryptedSymmetricKey);
        System.out.println("Decrypted Symmetric Key: " + decryptedSymmetricKey);
    }
}