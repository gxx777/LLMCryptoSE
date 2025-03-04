import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAEncryption3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAEncryption3(String privateKeyStr, String publicKeyStr) throws Exception {
        this.privateKey = KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr)));
        this.publicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyStr)));
    }

    /**
     * Encrypts the given symmetric key using RSA public key.
     *
     * @param symmetricKey the symmetric key to encrypt
     * @return the encrypted symmetric key as a Base64 encoded string
     * @throws Exception if encryption fails
     */
    public String encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey);
        return Base64.getEncoder().encodeToString(encryptedSymmetricKey);
    }

    /**
     * Decrypts the given encrypted symmetric key using RSA private key.
     *
     * @param encryptedSymmetricKey the encrypted symmetric key as a Base64 encoded string
     * @return the decrypted symmetric key
     * @throws Exception if decryption fails
     */
    public byte[] decryptSymmetricKey(String encryptedSymmetricKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
        return cipher.doFinal(encryptedKeyBytes);
    }

    public static void main(String[] args) {
        try {
            // Assuming you have RSA public and private keys in Base64 format
            String publicKeyStr = "..."; // Replace with your public key in Base64
            String privateKeyStr = "..."; // Replace with your private key in Base64

            RSAEncryption3 rsaEncryption = new RSAEncryption3(privateKeyStr, publicKeyStr);

            // Example symmetric key (e.g., AES key)
            byte[] symmetricKey = "ThisIsASymmetricKey1234567890".getBytes();

            // Encrypt the symmetric key
            String encryptedSymmetricKey = rsaEncryption.encryptSymmetricKey(symmetricKey);
            System.out.println("Encrypted Symmetric Key: " + encryptedSymmetricKey);

            // Decrypt the symmetric key
            byte[] decryptedSymmetricKey = rsaEncryption.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}