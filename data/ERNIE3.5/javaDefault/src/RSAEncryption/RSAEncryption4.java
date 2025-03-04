import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class RSAEncryption4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAEncryption4() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // 2048-bit RSA
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    public byte[] decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedKeyBytes);
    }

    public static void main(String[] args) {
        try {
            RSAEncryption4 rsa = new RSAEncryption4();

            // Generate a symmetric key (e.g., AES)
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] symmetricKey = secretKey.getEncoded();

            // Encrypt the symmetric key with RSA
            String encryptedSymmetricKey = rsa.encryptSymmetricKey(symmetricKey);
            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

            // Decrypt the symmetric key with RSA
            byte[] decryptedSymmetricKey = rsa.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + Arrays.toString(decryptedSymmetricKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}